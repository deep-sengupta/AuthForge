# Contributing to AuthForge

Thank you for contributing to AuthForge.

AuthForge is a security testing tool designed to help authorized testers identify authorization weaknesses such as BOLA and IDOR. Contributions should improve its accuracy, safety, usability, documentation, or maintainability without encouraging unauthorized testing.

## Before You Contribute

Please read the project documentation and understand the existing architecture before making substantial changes.

Use AuthForge only against systems you own or are explicitly authorized to test.

For security-sensitive changes, prefer clear, narrowly scoped pull requests that explain the security impact and the reasoning behind the implementation.

## Development Requirements

AuthForge requires Go 1.21 or newer.

Before opening a pull request, make sure the project builds successfully and run the available tests.

```bash
go test ./...
go build ./...
```

## Making Changes

Keep changes focused and avoid unrelated refactoring in the same pull request.

For authorization-analysis logic, include tests that cover normal behavior, negative cases, and boundary conditions.

For changes affecting request execution, mutation handling, side-effect verification, actor discovery, object ownership, authorization decisions, or finding verification, clearly describe how the change preserves the project's safe-by-default behavior.

Do not introduce behavior that silently enables target execution, mutating requests, or side-effect verification.

Avoid logging secrets, session tokens, authorization headers, passwords, or other sensitive captured traffic.

## Pull Requests

A good pull request should include:

- A clear description of what changed and why.
- The relevant issue or problem being addressed, when applicable.
- Tests or validation performed.
- Any security, compatibility, or behavior considerations.
- Documentation updates when user-visible behavior or configuration changes.

Keep commit messages and pull request descriptions concise and specific.

## Security-Sensitive Contributions

Do not disclose a newly discovered vulnerability in a public issue or pull request. Follow the process in `SECURITY.md` instead.

Changes that affect authorization verification, request construction, identity handling, or execution controls may require additional review before merging.

## Code Style

Follow standard Go conventions and keep implementations simple, explicit, and easy to audit.

Prefer small functions, clear error handling, and tests that make security assumptions visible.

## Responsible Testing

Use local test fixtures, staging environments, mock services, or systems for which you have explicit authorization.

Do not include real credentials, production secrets, private customer data, or unauthorized target information in commits, tests, examples, or issue reports.

## Contributor Agreement

By submitting a contribution, you agree that your contribution is provided under the repository's applicable license and that you have the right to submit it.
