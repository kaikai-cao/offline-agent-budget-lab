E4.7.2 — Read-only Owner NV Counter preflight

This package contains one PowerShell script:
  scripts\probe_e4_7_2_owner_counter_preflight.ps1

Run from an elevated PowerShell session on the target Windows machine.
The script sends only:
  - TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)
  - TPM2_GetCapability(TPM_CAP_HANDLES)
  - TPM2_NV_ReadPublic (for the E4.5 baseline indices and candidate handle)

It does NOT send NV_DefineSpace, NV_Increment, NV_Read, NV_Write,
NV_UndefineSpace, TPM2_Clear, or TPM2_HierarchyControl.

The candidate is 0x01BFFFFE, inside the TCG convention's Owner NV range.
A PASS means only that the candidate was not defined at probe time, the
previous E4.5 public Names match, shEnable is set, and TPM is not in lockout.
It does NOT guarantee NV storage capacity or availability for an
ORDERLY=CLEAR counter and does NOT authorize any mutating TPM command.

OwnerAuthSet is reported as a state bit only. The script never reads,
requests, prints, or changes OwnerAuth.
