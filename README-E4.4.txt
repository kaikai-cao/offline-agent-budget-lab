E4.4 TPM read-only command probe

Purpose
-------
Use the already working TBS context API to submit only read-only TPM2_GetCapability commands:
1. TPM_CAP_COMMANDS: inspect advertised command codes around the NV command range.
2. TPM_CAP_HANDLES from 0x01000000: enumerate currently defined NV-index handles.

Safety boundary
---------------
This script does NOT submit TPM2_NV_DefineSpace, TPM2_NV_UndefineSpace,
TPM2_NV_Write, TPM2_NV_Increment, TPM2_Clear, or any other mutating TPM command.
It does not modify BIOS, Windows registry, services, or TPM configuration.

Important interpretation
-----------------------
- TBS return code 0 means TBS accepted/completed the submission path.
- TPM response code 0 means the TPM command itself succeeded.
- TPM_CAP_COMMANDS indicates advertised TPM implementation support only.
  It does not prove that Windows/TBS policy permits a future mutating command.
- TPM_CAP_HANDLES only enumerates current handles in the queried range.
  An empty result does not mean the TPM lacks NV storage capability.
- A successful read-only capability query is not an NV write-permission test.

Run
---
Open an elevated Windows PowerShell and run:
  .\probe_e4_tpm_readonly_commands.ps1

Expected report
---------------
Capture the complete output, including TBS return values and TPM response codes.
Do not proceed to any NV write/counter test based only on command advertisement.
