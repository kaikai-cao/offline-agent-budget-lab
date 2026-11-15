"""Durable single-writer broker model for TPM NV Counter integration.

This is a SOFTWARE-ONLY experiment. FileBackedCounter simulates a hardware
monotonic counter. No TPM, TBS, Windows TPM API, or hardware is accessed.

The broker uses a cross-process file lock plus a SQLite WAL journal. This
models one cooperating broker domain on one host. It does not protect against
malicious local administrators, code that bypasses the broker, cloned hosts,
or tampering with both the database and the simulated counter state.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any
import uuid


class BrokerError(RuntimeError):
    pass


class BudgetExceeded(BrokerError):
    pass


class OperationBindingConflict(BrokerError):
    pass


class OperationNotApplied(BrokerError):
    pass


class BrokerIndeterminate(BrokerError):
    pass


class CounterStateError(BrokerError):
    pass


class InjectedCrash(BrokerError):
    """A deterministic fault injected after a durable protocol boundary."""


@dataclass(frozen=True)
class IncrementResponse:
    """Like TPM2_NV_Increment, the modeled response carries status only."""

    response_code: int = 0


@dataclass(frozen=True)
class Receipt:
    lease_id: str
    operation_id: str
    request_digest: str
    counter_value: int


class CrossProcessFileLock:
    """Advisory exclusive lock shared by processes on one host.

    Windows uses msvcrt byte-range locking; POSIX uses flock. The lock file is
    not a security boundary against an administrator or a process that ignores
    this broker protocol.
    """

    def __init__(self, path: str | Path, timeout_seconds: float = 30.0) -> None:
        self.path = Path(path)
        self.timeout_seconds = timeout_seconds
        self._fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+b", buffering=0)
        if os.fstat(self._fh.fileno()).st_size == 0:
            self._fh.write(b"\0")
            self._fh.flush()
        deadline = time.monotonic() + self.timeout_seconds
        if os.name == "nt":
            import msvcrt

            while True:
                self._fh.seek(0)
                try:
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                    return self
                except OSError:
                    if time.monotonic() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(f"Timed out acquiring broker lock: {self.path}")
                    time.sleep(0.05)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        self._fh.close()
                        self._fh = None
                        raise TimeoutError(f"Timed out acquiring broker lock: {self.path}")
                    time.sleep(0.05)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is None:
            return
        try:
            self._fh.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None


class FileBackedCounter:
    """Persistent counter emulator; each read/increment is individually locked.

    The increment response intentionally contains no value. The persistent
    JSON file is a test double, NOT secure storage and NOT a TPM substitute.
    """

    def __init__(self, state_path: str | Path, initial_value: int = 0) -> None:
        self.path = Path(state_path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        if not isinstance(initial_value, int) or initial_value < 0:
            raise ValueError("initial_value must be a non-negative integer")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with CrossProcessFileLock(self.lock_path):
            if not self.path.exists():
                self._write_value_unlocked(initial_value)

    def _read_value_unlocked(self) -> int:
        try:
            obj = json.loads(self.path.read_text(encoding="utf-8"))
            value = obj["counter_value"]
        except Exception as exc:
            raise CounterStateError(f"Counter emulator state is unreadable: {exc}") from exc
        if not isinstance(value, int) or value < 0:
            raise CounterStateError("Counter emulator state is not a non-negative integer")
        return value

    def _write_value_unlocked(self, value: int) -> None:
        payload = json.dumps({"counter_value": value}, sort_keys=True) + "\n"
        tmp = self.path.with_name(self.path.name + f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def read(self) -> int:
        with CrossProcessFileLock(self.lock_path):
            return self._read_value_unlocked()

    def increment(self) -> IncrementResponse:
        with CrossProcessFileLock(self.lock_path):
            value = self._read_value_unlocked()
            self._write_value_unlocked(value + 1)
        return IncrementResponse(response_code=0)


class SQLiteJournal:
    """SQLite WAL store for durable intent, receipt and monotonic anchor."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    pre_counter_value INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    counter_value INTEGER,
                    updated_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    operation_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    counter_value INTEGER NOT NULL UNIQUE,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    @contextmanager
    def _db(self):
        con = self._connect()
        try:
            yield con
        finally:
            con.close()

    def initialize(self, lease_id: str, quota_limit: int, baseline: int) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                values = dict(con.execute("SELECT key, value FROM meta").fetchall())
                if not values:
                    seed = {
                        "lease_id": lease_id,
                        "quota_limit": str(quota_limit),
                        "expected_counter_value": str(baseline),
                        "health": "READY",
                        "health_reason": "",
                    }
                    con.executemany("INSERT INTO meta(key,value) VALUES(?,?)", seed.items())
                else:
                    if values.get("lease_id") != lease_id:
                        raise ValueError("lease_id does not match the existing journal")
                    if values.get("quota_limit") != str(quota_limit):
                        raise ValueError("quota_limit does not match the existing journal")
                con.commit()
            except Exception:
                con.rollback()
                raise

    def meta(self) -> dict[str, str]:
        with self._db() as con:
            return dict(con.execute("SELECT key,value FROM meta").fetchall())

    def set_health_indeterminate(self, reason: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE meta SET value='INDETERMINATE' WHERE key='health'")
            con.execute("UPDATE meta SET value=? WHERE key='health_reason'", (reason,))
            con.commit()

    def create_intent(self, operation_id: str, lease_id: str, digest: str, pre_value: int) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO operations(operation_id,lease_id,request_digest,pre_counter_value,status) "
                    "VALUES(?,?,?,?, 'PENDING')",
                    (operation_id, lease_id, digest, pre_value),
                )
                con.commit()
            except Exception:
                con.rollback()
                raise

    def get_operation(self, operation_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute(
                "SELECT operation_id,lease_id,request_digest,pre_counter_value,status,counter_value "
                "FROM operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        keys = ("operation_id", "lease_id", "request_digest", "pre_counter_value", "status", "counter_value")
        return dict(zip(keys, row))

    def pending_operations(self) -> list[dict[str, Any]]:
        with self._db() as con:
            rows = con.execute(
                "SELECT operation_id,lease_id,request_digest,pre_counter_value,status,counter_value "
                "FROM operations WHERE status='PENDING' ORDER BY operation_id"
            ).fetchall()
        keys = ("operation_id", "lease_id", "request_digest", "pre_counter_value", "status", "counter_value")
        return [dict(zip(keys, row)) for row in rows]

    def set_operation_status(self, operation_id: str, status: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE operations SET status=?, updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                "WHERE operation_id=?",
                (status, operation_id),
            )
            con.commit()

    def commit_receipt(self, row: dict[str, Any], counter_value: int) -> Receipt:
        receipt = Receipt(
            lease_id=row["lease_id"],
            operation_id=row["operation_id"],
            request_digest=row["request_digest"],
            counter_value=counter_value,
        )
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO receipts(operation_id,lease_id,request_digest,counter_value) VALUES(?,?,?,?)",
                    (receipt.operation_id, receipt.lease_id, receipt.request_digest, receipt.counter_value),
                )
                con.execute(
                    "UPDATE operations SET status='COMMITTED', counter_value=?, "
                    "updated_utc=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE operation_id=?",
                    (counter_value, receipt.operation_id),
                )
                con.execute(
                    "UPDATE meta SET value=? WHERE key='expected_counter_value'",
                    (str(counter_value),),
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
        return receipt

    def get_receipt(self, operation_id: str) -> Receipt | None:
        with self._db() as con:
            row = con.execute(
                "SELECT lease_id,operation_id,request_digest,counter_value FROM receipts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        return Receipt(*row) if row else None


class DurableCounterBroker:
    """One-lease durable broker model protected by a host-local process lock.

    `crash_at` is a deterministic fault-injection hook. It raises after a
    boundary, leaving SQLite and the persistent counter emulator as they were.
    Reconstruct a new broker instance to model process restart/recovery.
    """

    VALID_CRASH_POINTS = {None, "after_intent", "after_increment", "after_read", "after_receipt_commit"}

    def __init__(
        self,
        *,
        journal_path: str | Path,
        counter_state_path: str | Path,
        broker_lock_path: str | Path,
        lease_id: str,
        quota_limit: int,
        initial_counter_value: int = 0,
    ) -> None:
        if not isinstance(lease_id, str) or not lease_id.strip():
            raise ValueError("lease_id must be a non-empty string")
        if not isinstance(quota_limit, int) or quota_limit < 0:
            raise ValueError("quota_limit must be a non-negative integer")
        self.lease_id = lease_id
        self.quota_limit = quota_limit
        self.counter = FileBackedCounter(counter_state_path, initial_counter_value)
        self.journal = SQLiteJournal(journal_path)
        self.lock_path = Path(broker_lock_path)
        self.journal.initialize(lease_id, quota_limit, self.counter.read())

    def _trip(self, crash_at: str | None, point: str) -> None:
        if crash_at == point:
            raise InjectedCrash(f"Injected process interruption at {point}")

    def _check_health_and_anchor(self) -> int:
        meta = self.journal.meta()
        if meta.get("health") != "READY":
            raise BrokerIndeterminate(meta.get("health_reason") or "broker journal is marked indeterminate")
        expected = int(meta["expected_counter_value"])
        observed = self.counter.read()
        if observed != expected:
            reason = f"counter anchor mismatch: journal={expected}, counter={observed}"
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)
        return expected

    def _recover_pending_locked(self) -> None:
        pending = self.journal.pending_operations()
        if not pending:
            return
        if len(pending) != 1:
            reason = f"expected at most one pending intent; found {len(pending)}"
            for row in pending:
                self.journal.set_operation_status(row["operation_id"], "INDETERMINATE")
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)

        row = pending[0]
        meta = self.journal.meta()
        if meta.get("health") != "READY":
            raise BrokerIndeterminate(meta.get("health_reason") or "journal is indeterminate")
        expected = int(meta["expected_counter_value"])
        pre_value = int(row["pre_counter_value"])
        if pre_value != expected:
            reason = f"pending intent pre-value {pre_value} differs from journal anchor {expected}"
            self.journal.set_operation_status(row["operation_id"], "INDETERMINATE")
            self.journal.set_health_indeterminate(reason)
            raise BrokerIndeterminate(reason)

        observed = self.counter.read()
        delta = observed - pre_value
        if delta == 0:
            self.journal.set_operation_status(row["operation_id"], "NOT_APPLIED")
            return
        if delta == 1:
            # Under the process-lock + single-writer assumption, one visible
            # increment is attributable to this one durable pending intent.
            self.journal.commit_receipt(row, observed)
            return

        reason = f"pending intent recovery is ambiguous: pre={pre_value}, observed={observed}, delta={delta}"
        self.journal.set_operation_status(row["operation_id"], "INDETERMINATE")
        self.journal.set_health_indeterminate(reason)
        raise BrokerIndeterminate(reason)

    def consume(
        self,
        *,
        operation_id: str,
        request_digest: str,
        crash_at: str | None = None,
    ) -> Receipt:
        if crash_at not in self.VALID_CRASH_POINTS:
            raise ValueError(f"crash_at must be one of {sorted(x for x in self.VALID_CRASH_POINTS if x)} or None")
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise ValueError("operation_id must be a non-empty string")
        if not isinstance(request_digest, str) or not request_digest.strip():
            raise ValueError("request_digest must be a non-empty string")

        with CrossProcessFileLock(self.lock_path):
            existing = self.journal.get_operation(operation_id)
            if existing is not None:
                if (existing["lease_id"], existing["request_digest"]) != (self.lease_id, request_digest):
                    raise OperationBindingConflict("operation_id is already bound to another lease or request digest")
                if existing["status"] == "COMMITTED":
                    receipt = self.journal.get_receipt(operation_id)
                    if receipt is None:
                        reason = "operation is COMMITTED but its receipt is missing"
                        self.journal.set_health_indeterminate(reason)
                        raise BrokerIndeterminate(reason)
                    return receipt
                if existing["status"] == "NOT_APPLIED":
                    raise OperationNotApplied("this operation_id was not applied; use a new operation_id for a new attempt")
                if existing["status"] == "INDETERMINATE":
                    raise BrokerIndeterminate("this operation_id is marked INDETERMINATE")

            self._recover_pending_locked()

            # The pending intent may have been recovered as COMMITTED or NOT_APPLIED.
            existing = self.journal.get_operation(operation_id)
            if existing is not None:
                if existing["status"] == "COMMITTED":
                    receipt = self.journal.get_receipt(operation_id)
                    if receipt is None:
                        raise BrokerIndeterminate("recovered operation has no durable receipt")
                    return receipt
                if existing["status"] == "NOT_APPLIED":
                    raise OperationNotApplied("this operation_id was not applied; use a new operation_id for a new attempt")
                if existing["status"] == "INDETERMINATE":
                    raise BrokerIndeterminate("this operation_id is marked INDETERMINATE")

            before = self._check_health_and_anchor()
            if before >= self.quota_limit:
                raise BudgetExceeded(f"quota exhausted: counter={before}, quota={self.quota_limit}")

            self.journal.create_intent(operation_id, self.lease_id, request_digest, before)
            self._trip(crash_at, "after_intent")

            response = self.counter.increment()
            if response.response_code != 0:
                self.journal.set_operation_status(operation_id, "INDETERMINATE")
                reason = f"counter increment returned response code 0x{response.response_code:08X}"
                self.journal.set_health_indeterminate(reason)
                raise BrokerIndeterminate(reason)
            self._trip(crash_at, "after_increment")

            after = self.counter.read()
            self._trip(crash_at, "after_read")
            if after != before + 1:
                self.journal.set_operation_status(operation_id, "INDETERMINATE")
                reason = f"counter transition was not exactly +1: before={before}, after={after}"
                self.journal.set_health_indeterminate(reason)
                raise BrokerIndeterminate(reason)

            row = self.journal.get_operation(operation_id)
            if row is None:
                raise BrokerIndeterminate("durable intent disappeared before receipt commit")
            receipt = self.journal.commit_receipt(row, after)
            self._trip(crash_at, "after_receipt_commit")
            return receipt

    def inspect(self) -> dict[str, Any]:
        """Read-only model diagnostics; does not increment the counter."""
        with self._lock_context():
            meta = self.journal.meta()
            current = self.counter.read()
            pending = self.journal.pending_operations()
        return {
            "lease_id": meta.get("lease_id"),
            "quota_limit": int(meta.get("quota_limit", "0")),
            "health": meta.get("health"),
            "health_reason": meta.get("health_reason", ""),
            "expected_counter_value": int(meta.get("expected_counter_value", "0")),
            "observed_counter_value": current,
            "pending_operation_ids": [r["operation_id"] for r in pending],
        }

    def _lock_context(self):
        return CrossProcessFileLock(self.lock_path)
