# IR-001 — Incident Response Playbook

## Purpose

Defines response procedures for DWITP incidents.

---

# Severity Levels

P1 — Critical

P2 — High

P3 — Medium

P4 — Low

---

# Tor Failure

Actions:

1. Halt crawler.
2. Log event.
3. Notify operator.
4. Validate Tor.
5. Resume operations.

---

# Queue Failure

Actions:

1. Halt collection.
2. Preserve evidence.
3. Restore queue.
4. Resume processing.

---

# Crawler Compromise

Actions:

1. Destroy VM.
2. Rotate secrets.
3. Rebuild infrastructure.
4. Audit evidence.

---

# Prompt Injection Campaign

Actions:

1. Quarantine source.
2. Disable AI processing.
3. Review evidence.
4. Update reputation score.

---

# Data Poisoning Event

Actions:

1. Freeze source.
2. Require analyst review.
3. Recalculate confidence.
4. Audit findings.

---

# End of Document