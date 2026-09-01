# AuthForge

> AuthForge is a Burp-driven authorization testing tool that learns actors, roles, tenants, and object relationships from captured HTTP traffic. It uses this information to plan and verify cross-user and cross-tenant authorization tests, with a focus on BOLA/IDOR detection.

## How It Works

```text
Burp Traffic
     |
     ▼
Actor Discovery
     |
     ▼
Object & Ownership Mapping
     |
     ▼
Authorization Model
     |
     ▼
Cross-User / Cross-Tenant Test Planning
     |
     ▼
Control Object Verification
     |
     ▼
Verified BOLA / IDOR Findings
     |
     ▼
Authorization & Attack Graphs
     |
     ▼
Regression Invariants
````

---

## Key Features

### Automatic Actor Discovery

AuthForge identifies actors from authenticated Burp traffic and reuses captured authentication data. It can detect JWT identity, role, and tenant claims, as well as common identity headers.

Explicit YAML actors can also be provided when automatic discovery is insufficient.

### Verified BOLA / IDOR Detection

Findings are not based on a single unexpected response. AuthForge compares source and target actors using independent control objects to determine whether an authorization boundary was actually bypassed.

### Authorization & Attack Graphs

AuthForge builds structured authorization graphs and attack paths showing actors, objects, authorization decisions, and verified attack relationships.

DOT output preserves allow/deny state for easier analysis and visualization.

### Safe by Default

AuthForge runs in dry-run mode by default. No target requests are made unless execution is explicitly enabled.

Mutating requests such as `POST`, `PUT`, `PATCH`, and `DELETE` require the additional `--allow-mutations` flag.

Side-effect verification requires both mutation permission and `--verify-side-effects`.

---

## Installation

Requires Go 1.21+.

```bash
go build -o authforge
```

Or download a prebuilt binary from the Releases page.

---

## Usage

### Plan Only

The default mode analyzes the Burp capture without making network requests.

```bash
./authforge -config examples/init.yaml
```

### Read-Only Execution

Enable execution without allowing mutating authorization probes.

```bash
./authforge -config examples/init.yaml -execute
```

### Full Staging Run

Enable mutations and side-effect verification explicitly.

```bash
./authforge \
  -config examples/init.yaml \
  -execute \
  -allow-mutations \
  -verify-side-effects
```

Run:

```bash
./authforge -h
```

to see all available flags.

---

## Outputs

| File                      | Description                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------- |
| `authforge-report.json`   | Findings, actors, observations, authorization graphs, attack paths, and generated tests |
| `authforge-report.html`   | Human-readable security report                                                          |
| `authforge-graph.dot`     | Authorization and attack-path graph                                                     |
| `authforge-baseline.json` | Authorization invariants for regression testing                                         |

---

## Documentation

For deeper technical details:

* [Architecture](docs/ARCHITECTURE.md)
* [Verification](docs/VERIFICATION.md)

---

## Coverage

AuthForge can only reason about actors, objects, and relationships observed in the supplied Burp traffic.

Broader traffic across users, roles, tenants, and endpoints provides better coverage and more representative authorization analysis.

---

## Responsible Use

Use AuthForge only against systems you own or are explicitly authorized to test.

---
