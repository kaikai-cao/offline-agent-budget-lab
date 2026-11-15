E2 State-Trust Comparison v0.1

This is an additive experiment package. It preserves E0/E1 modules and adds:
- src/budget_lab/state_trust.py
- tests/test_e2_state_trust.py
- docs/e2-state-trust-comparison-v0.1.md
- run_e2_tests.ps1

Run E2 only:
  .\run_e2_tests.ps1

Run the complete regression suite:
  .\run_tests.ps1

IMPORTANT:
- SharedAtomicSpendAuthority and SharedRootAllocationRegistry are in-memory
  single-process reference models for online atomic authority. They are not
  distributed databases or consensus implementations.
- MonotonicStateEmulator is not real TEE/secure-element code. It models the
  API/state assumption that must later be evaluated against actual hardware.
- No E0 production module is changed by this stage.
