E4.7.1 — Dedicated TPM NV Counter Design Review

This package contains the design review only.
No executable TPM command script is included.
No TPM command is sent by extracting or reading these files.

Read:
  docs/E4.7.1-counter-design-review-v0.1.md

Decision:
  Candidate owner-range handle: 0x01BFFFFE (subject to fresh read-only preflight)
  NV type: TPM_NT_COUNTER
  Name algorithm: SHA-256 (0x000B)
  Data size: 8 bytes
  Attributes: 0x00040014 (AUTHREAD | AUTHWRITE | COUNTER)
  ORDERLY: CLEAR

This is a persistence primitive experiment, not yet a claim of protection against
an attacker who can use Owner authorization or undefine/redefine the index.
Do not run NV_DefineSpace, NV_Increment, or NV_UndefineSpace at this stage.
