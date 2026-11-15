E4.6 TPM 2.0 read-only properties probe

1. Extract this package into D:\Research\offline-agent-budget-lab.
2. Open an elevated PowerShell window.
3. Run:
     Set-Location D:\Research\offline-agent-budget-lab
     .\probe_e4_tpm_properties.ps1
4. Send the complete output for review.

The script submits only TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES).
No NV index or NV counter is modified.

Read docs\E4.6-tpm-properties-probe-v0.1.md before interpreting results.
