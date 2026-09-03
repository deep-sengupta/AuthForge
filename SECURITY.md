# Security Policy

## Supported Versions

Security fixes are applied to the latest version of AuthForge on the `master` branch.

If you are using an older version, please update to the latest available version before reporting an issue unless doing so would prevent you from reproducing the security problem.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, pull requests, discussions, or other public channels.

Instead, contact the repository owner privately through the contact information available on the repository owner's GitHub profile.

Please include as much of the following information as possible:

- A clear description of the vulnerability.
- The affected version or commit.
- Steps to reproduce the issue.
- The expected and actual behavior.
- The potential security impact.
- Any proof of concept that can be shared safely.
- Suggested mitigations, if available.

Do not include real credentials, session tokens, private customer data, or other sensitive information unless it is strictly necessary and can be shared through an agreed private channel.

## What to Expect

After receiving a report, the maintainer will review the information and may request additional details.

Reports will be assessed for reproducibility, severity, affected versions, and potential impact. A fix, mitigation, or other response will be prepared when appropriate.

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

## Scope

Security issues may include, but are not limited to:

- Authentication or authorization bypasses in AuthForge itself.
- Unsafe handling of captured credentials or authentication material.
- Unexpected request execution or mutation behavior.
- Failures of dry-run or execution safety controls.
- Sensitive information exposure.
- Dependency vulnerabilities with a meaningful impact on AuthForge users.
- Malicious input handling that can compromise the environment running AuthForge.

## Responsible Disclosure

AuthForge is intended for authorized security testing. Vulnerability reports should be performed responsibly and must not involve unauthorized access to systems, data, or infrastructure.

Do not use a suspected vulnerability to access, modify, destroy, or exfiltrate information beyond what is necessary to demonstrate the issue safely.

Thank you for helping keep AuthForge and its users secure.
