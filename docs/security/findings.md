# SilentSnake adversary findings log

Append-only. Written by the `adversary` agent (`.claude/agents/adversary.md`); one entry per finding, IDs `ADV-0001` upward, never reused. Entries are never deleted or rewritten: status changes are appended as dated lines under the entry.

**Statuses:** `open` → `fixed` (only after the adversary re-tests and confirms) or `accepted-risk` (only with Ronin's written approval, quoted in the status line).
A milestone is **blocked** while any `critical` or `high` finding is `open`.

## Index

| ID | Severity | Title | Milestone | Found | Status |
|---|---|---|---|---|---|

## Findings

<!--
Template for each entry (copy below this line):

### ADV-0000: <title>
- **Severity:** critical | high | medium | low | info
- **Milestone / commit:** <component> @ <hash>
- **Found:** YYYY-MM-DD (report: pentest-YYYY-MM-DD.md)
- **Violates:** <file and line in CLAUDE.md / dependencies.json / silentsnake.yaml>
- **NIST SP 800-53:** <control>
- **Reproduce:** <steps>
- **Evidence:** <command and output>
- **Suggested fix:** <suggestion; builder decides>
- **Status log:**
  - YYYY-MM-DD open
-->
