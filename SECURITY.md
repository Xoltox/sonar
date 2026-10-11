# Security Policy

## Supported versions

Only the latest release of Sonar receives security fixes. Please check that
you are running the newest version from the
[releases page](https://github.com/Xoltox/sonar/releases/latest) before
reporting an issue.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report vulnerabilities privately through GitHub's private vulnerability
reporting:

1. Go to the [Security tab](https://github.com/Xoltox/sonar/security) of the repository.
2. Choose **Report a vulnerability** to open a draft Security Advisory.
3. Describe the issue, the affected version, your operating system, and steps
   to reproduce it.

You can expect an acknowledgement within a few days. Once a fix is ready, it
will be released and the advisory published with credit to the reporter, unless
you prefer to remain anonymous.

## Scope and security notes

- The web UI (`sonar serve`, `sonar ui`, `--serve`) binds to `127.0.0.1` by
  default, so only the local machine can reach it.
- Every API request requires a per-process token that is generated at startup
  and embedded in the served page.
- Requests are accepted only for an allowlist of `Host` header values, and
  cross-site requests are rejected.
- Binding the web UI to a non-loopback address (for example `0.0.0.0:8080`)
  exposes it to the network. The UI has no user authentication, so anyone who
  can reach it can start scans and send Wake-on-LAN packets. Only do this on a
  network you trust.
- Sonar is intended for networks you own or administer. Use it only where you
  are authorized to scan.
