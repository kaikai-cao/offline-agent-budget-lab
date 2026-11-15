E4.7.3 - Controlled TPM NV Counter Persistence Experiment

This package performs one carefully scoped hardware experiment on the local TPM.
It is NOT a production security feature and does NOT prove protection against a
malicious Windows administrator or TPM Owner-authorized party.

Phases (run in this order, in elevated PowerShell, under the same Windows account):
  0. scripts\00-offline-marshalling-self-test.ps1
     FIRST GATE. Compiles the C# helper and checks command byte layouts and
     response parsers OFFLINE. It does not open TBS and does not send any TPM command.
     Stop if this script does not print Offline marshalling self-test: PASS.
  1. scripts\01-create-and-increment.ps1
     Only after Phase 0 passes. Rechecks the 16 original NV Names, hierarchy state,
     candidate handle, and TPM_CAP_COMMANDS advertisement for all required commands;
     defines the dedicated Counter, then sends exactly one NV_Increment after a
     second explicit typed confirmation. It verifies the TPMA_NV_WRITTEN transition
     and corresponding NV Name change, then records the observed post-increment value.
  2. Restart Windows normally. Do NOT clear/reset the TPM and do NOT use
     shutdown /s if Fast Startup could produce a hybrid shutdown.
  3. scripts\02-verify-after-reboot.ps1
     Reads public metadata and the counter value, then compares it byte-for-byte
     with the pre-reboot value. It refuses to claim success if LastBootUpTime did
     not advance.
  4. scripts\03-cleanup.ps1
     After a verified reboot (or a recorded no-increment abort), it checks the
     candidate Name and original 16 Names, asks for explicit confirmation, and
     undefines ONLY the candidate handle. It verifies the original 16 NV Names
     and NV counts afterwards. The script handles the expected NV Name change
     when TPMA_NV_WRITTEN changes from CLEAR to SET.

If the DefineSpace attempt is interrupted and the candidate does not exist,
run 00-abandon-if-candidate-absent.ps1 to remove only the local DPAPI files.
If an Increment response is uncertain, run 01b-capture-value-before-reboot.ps1.
It distinguishes a written counter from WRITTEN=CLEAR + TPM_RC_NV_UNINITIALIZED;
never resend NV_Increment after an uncertain outcome.
If the candidate exists, do not remove the state/auth files; inspect and clean
up only after confirming its Name. If an Undefine response/verification is interrupted, do NOT rerun 03-cleanup.ps1;
run 04-finalize-if-candidate-absent.ps1 only after it proves the candidate is absent,
all original Names match, and counts return to 16/4; this finalizer sends no TPM writes.

The random NV authValue is stored using Windows DPAPI via Export-Clixml under:
  %LOCALAPPDATA%\OfflineAgentBudgetLab\E4.7.3\
Run all phases under the same Windows account on the same machine. Never copy
counter-auth.dpapi.xml to another computer or account.

NO script calls TPM_Clear. Do not manually run NV_DefineSpace, NV_Increment,
NV_UndefineSpace, Clear-Tpm, Initialize-Tpm, or any unrelated TPM command.

Do not run Phase 1 if Phase 0 fails or if the C# helper does not compile. Do not rerun
Phase 1 after a state file exists; follow the recovery instructions above. TPM counter
initial values are not assumed to be 1; the package records the observed C1 and compares
it with C2 after a real restart.
