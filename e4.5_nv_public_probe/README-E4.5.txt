E4.5 TPM NV Public Metadata Read-Only Inspection

Run from elevated Windows PowerShell:

  .\probe_e4_nv_public_readonly.ps1

The script sends TPM2_NV_ReadPublic for the 16 NV handles observed in E4.4.
It does not read NV data and does not define, delete, write, increment, or clear any NV index.

Return the full output for analysis. Do not perform manual NV modifications.
