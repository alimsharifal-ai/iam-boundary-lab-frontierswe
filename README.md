# Cloud IAM privilege boundary lab

An original, fully offline security benchmark sample. The agent implements a synthetic IAM evaluator that prevents privilege escalation by enforcing explicit denies and independent policy intersections. No production account, credentials, or endpoints are involved.

This is a Harbor task. `environment/` is agent-visible. `solution/` is used only by the oracle. `tests/` is used only by the verifier; neither should be copied into the agent image.

Run the client checker first. Then run `harbor run -p tasks/iam-boundary-lab -a oracle` and `harbor run -p tasks/iam-boundary-lab -a nop`. Results must be copied from terminal output, not inferred from local tests.

Estimated expert time: 10 to 20 hours. Original code is MIT licensed.
