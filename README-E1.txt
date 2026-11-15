E1 Attack Experiments v0.1 — baseline findings

The original E1-04 finding (evidence-supplied executor key was treated as a trust
anchor) is remediated by E1.1. Current reconciliation requires an external
trusted_executor_keys mapping. See docs/e1.1-executor-trust-binding.md.

Run focused attack tests: .\run_e1_attacks.ps1
Run complete regression: .\run_tests.ps1

The tests demonstrate both prevented and successful attacks. A passing attack
test is not equivalent to the system preventing the attack.
