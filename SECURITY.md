# Security reporting

Do not post exploitable vulnerability details or unsanitized diagnostic artifacts
in a public issue. Reports may contain process command lines, identities, security
labels, paths, policy intent or historical access data.

Use this repository's supported private vulnerability-reporting mechanism. On
GitHub, if private reporting is enabled, use **Security → Advisories → Report a
vulnerability**. Availability depends on repository settings; this project does not
claim that it is enabled or invent a private contact address. If no private channel
is advertised, ask maintainers for a private reporting channel without disclosing
the exploit or sensitive data publicly.

Include the affected version, Linux/Python environment, minimal sanitized
reproduction, observed versus expected behavior and impact. Avoid collecting
unrelated user/process data or changing a production system to reproduce an issue.

There is no promised response SLA or published long-term support window. Maintainers
should establish reporting availability and supported releases before publication.
The tool is a model, not an enforcement boundary; ordinary documented limitations
are described in the [threat model](docs/threat-model.md).
