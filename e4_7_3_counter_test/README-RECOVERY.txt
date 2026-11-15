E4.7.3 Recovery Patch v0.1

This patch is for the state where the first run successfully defined NV index 0x01BFFFFE,
then stopped in PowerShell response validation before the increment confirmation prompt.

IMPORTANT:
- Do NOT rerun 01-create-and-increment.ps1.
- Preserve the local state and DPAPI auth files under %LOCALAPPDATA%\OfflineAgentBudgetLab\E4.7.3.
- Run scripts\00-fix-common-uint32-mask.ps1.
- Run scripts\00-offline-marshalling-self-test.ps1.
- Then run scripts\01a-resume-after-define.ps1.
- The resume script does not define an NV index. It verifies the existing index and asks for one explicit increment confirmation.
- If an increment outcome is uncertain, NEVER retry blindly.

See docs\E4.7.3-recovery-after-define-helper-failure-v0.1.md.
