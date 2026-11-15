E4.7 Dedicated TPM NV Counter Experiment Design v0.1

This is a DESIGN-ONLY package. It does not include an executable TPM command script.
No TPM index may be defined, written, incremented, or deleted based solely on this package.

Read:
  docs\E4.7-dedicated-nv-counter-design-v0.1.md

The next decision is to review the candidate owner handle, authorization, TPMA_NV flags,
and cleanup/recovery plan. Only after that review should a separate explicit approval be
requested for a controlled TPM mutation experiment.
