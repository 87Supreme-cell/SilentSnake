# Secrets and key handling

`.gitignore` is a convenience, not a control. These rules apply to the repo, the build, CI and the running product. The `adversary` agent hunts for violations on every run.

## What secrets exist
| Secret | Where it lives | Never |
|---|---|---|
| Machine signing and encryption keys | Sealed: TPM 2.0, else kernel keyring / OS secret store with user passphrase (CLAUDE.md §3) | On disk unsealed, in the repo, readable by the LLM sandbox |
| Local API token | Generated at first run, `$XDG_DATA_HOME/silentsnake/config/`, mode `0600` | In env vars, argv, logs, URLs or the repo |
| Commercial LLM API key (off by default) | User's OS secret store, set by the user | In config files in the repo, logs, prompts |
| Release signing (cosign) | CI secret store or keyless OIDC | In the repo or CI logs |
| Dependency registry credentials | None expected: public dependencies need no credentials. If one is ever needed: user-level config, `0600` | In the repo, build scripts, CI logs |

## Rules
1. **Nothing secret is ever committed**, encrypted or not. If an encrypted-in-repo secret is ever needed, propose a tool (for example sops + age) to Ronin first; it's a new dependency.
2. **Commit gate:** `scripts/hooks/pre-commit` runs on every commit and fails closed. Enable it once per clone: `git config core.hooksPath scripts/hooks`. CI re-runs `gitleaks` over full history on every push.
3. **Secrets never travel in env vars or argv.** Pass them via file descriptors or `0600` files, read once, then `zeroize`.
4. **Redact everywhere:** logs, errors, panics, API responses, LLM prompts, audit entries and security reports show at most the type, the first 4 characters and a SHA-256 fingerprint.
5. **No core dumps** from processes holding keys (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`).
6. **Test keys are generated during the test run** and discarded; no key fixtures in the repo.
7. **A leaked secret is rotated**, not just deleted. Git history rewrites don't un-leak anything already pushed or cloned.
