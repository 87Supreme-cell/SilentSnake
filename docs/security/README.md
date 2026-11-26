# Security reports

- `findings.md`: running, append-only log of every adversary finding and its status.
- `pentest-YYYY-MM-DD.md`: one report per adversary run (after each backend component and before every release, per CLAUDE.md section 7).

## Report template

```markdown
# Pentest YYYY-MM-DD: <milestone>

- **Commit:** <hash>
- **Scope:** <components and threat areas tested>
- **Verdict:** blocked | clear

## Tested
<area, method, commands, result>

## New findings
<ADV IDs with one-line summaries; full entries live in findings.md>

## Re-tests of earlier findings
<ADV ID: still open | fixed (evidence)>

## Not yet testable
<area and why>
```
