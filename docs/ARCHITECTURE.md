# AuthForge  Architecture

AuthForge is organized around a deterministic authorization-intelligence pipeline:

`Burp capture → actor inference → object discovery → baseline/plan → learned ownership → test planner → verified execution → attack graph → invariants/regression`

## Actor inference

Authenticated Burp requests are grouped by captured auth material. JWT claims and common identity headers are used to infer user, role, and tenant metadata. Explicit YAML actors can override or enrich the inferred metadata. Credentials are never invented.

## Safe execution model

Plan/dry-run is the default. Network probes require `executeTests` / `--execute`. Mutating HTTP methods additionally require `allowMutations` / `--allow-mutations`. Side-effect verification requires both execution and mutation permission plus `verifySideEffects`.

## Verified object authorization

A BOLA/IDOR proof uses two distinct object relationships: a source object that the source actor can access and a control object independently accessible by the target actor. The source actor must be denied the target control object, establishing ownership separation. The target then successfully accesses the source-owned object with its own authorization context; the target does not have to be denied first, because that would contradict the very access being verified. This also avoids mislabeling an already-captured unauthorized access as merely a regression.

## Graph artifacts

The authorization graph models actor/role/tenant/endpoint/action/object relationships and records allow/deny signals. Verified findings add first-class finding/path nodes and ordered attack-step edges. JSON and DOT therefore retain the same essential decision state.

## Coverage

Concrete ownership inference depends on representative Burp traffic. The planner can mutate observed identifiers, but a missing object/endpoint in the capture cannot be magically verified.
