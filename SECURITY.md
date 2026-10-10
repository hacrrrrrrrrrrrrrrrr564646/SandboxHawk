# Security policy

SandboxHawk is intended for local, authorized testing of V8 builds and JavaScript engines.

- Do not use it against systems or binaries you do not own or have explicit permission to test.
- Run fuzzing in a disposable environment without secrets, with restricted network access and resource limits.
- Preserve original testcases and logs; verify findings manually before reporting.
- A crash, timeout, sanitizer message, or behavioral difference is not by itself proof of a V8 sandbox escape.
- Do not publish exploit payloads or use this tool to access data outside an authorized test environment.

For a security issue in SandboxHawk itself, use GitHub's private vulnerability reporting feature if enabled, or contact the maintainers through the repository profile.
