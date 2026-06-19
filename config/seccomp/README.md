# Seccomp Profiles

## Status: Placeholder — Not a Security Control

- **`python.json`**: `SCMP_ACT_ALLOW` — allows all syscalls. This is effectively seccomp disabled. It exists so every service gets a seccomp profile path without crashing. **Do not rely on this for security.**
- **`crawler.json`**: Hand-authored allowlist for the Tor crawler. Untested against real crawling workloads — may block legitimate syscalls or miss attack surfaces.

Until production-grade profiles are generated, the real container hardening comes from: read-only rootfs, `cap_drop: ALL`, `no-new-privileges:true`, and non-root user.

## Generating Production Profiles

Run each service under strace during integration testing:

```bash
docker run --security-opt seccomp=unconfined --rm \
  -it dwitp/<service> strace -f -e trace=all -o /tmp/syscalls.log

# Extract unique syscall names
grep ^[a-z] /tmp/syscalls.log | sed 's/(.*//' | sort -u
```

Build a profile from the observed set. Test exhaustively — missing a single syscall causes the service to crash with `SIGSYS`.
