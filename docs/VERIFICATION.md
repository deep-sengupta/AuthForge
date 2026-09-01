# Verification and safety

The test suite covers:

- automatic JWT/header actor and role/tenant discovery
- object discovery and host/port exclusion
- adaptive identifier mutation
- behavioral similarity
- verified cross-user BOLA using distinct source/control objects
- structured attack-path graph creation
- DOT allow/deny export
- authorization regression detection
- dry-run protection against live requests

Recommended operating modes:

1. **Plan:** default. No target network calls; inspect generated tests first.
2. **Read-only execution:** `--execute`. Cross-user/cross-tenant read probes can run.
3. **Mutation execution:** `--execute --allow-mutations`. POST/PUT/PATCH/DELETE probes are allowed.
4. **Side-effect verification:** add `--verify-side-effects` only on a disposable/staging target with rollback/test data.
