# PR #10: fix: install.sh bug fixes and reliability improvements

- **URL**: https://github.com/TheRealFREDP3D/Kali-VM-Setup/pull/10
- **Branch**: `v1.1-improvements` → `main`
- **Author**: TheRealFREDP3D
- **Commit**: `207b0f9`
- **Date**: Jul 3, 2026
- **Status**: Open

---

## Summary

Resolves multiple bugs and reliability issues in `install.sh`. Single file changed: +27 / -37 lines.

---

## Bugs Fixed

| Bug | Description | Fix |
|-----|-------------|-----|
| Duplicate sections | "Final Cleanup" and "Optional Extras" blocks appeared twice, causing cleanup to run twice and duplicate prompts | Removed duplicates, restructured into single 8/9/10 flow |
| Glob expansion | `rm -rf "/home/$TARGET_USER/.cache/*"` — `*` inside quotes treated as literal character | Moved quote before wildcard: `"/home/$TARGET_USER/.cache/"*` |
| `local` at top level | `local oh_my_zsh_install_script` used outside any function | Removed `local` keyword |
| `cd` leaking | `cd "/home/$TARGET_USER/CTF/notes"` permanently changed script working directory | Wrapped in subshell `(...)` |
| Root-owned git repo | `git init`/`git commit` as root left notes directory unwritable by target user | Added `chown -R` after subshell |
| Hardcoded sudoers | `/etc/sudoers.d/kali` hardcoded regardless of target user | Changed to `/etc/sudoers.d/$TARGET_USER` |
| `ufw enable` hang | Interactive prompt blocked non-interactive execution | `yes \| ufw enable` |

## Improvements

| Change | Before | After |
|--------|--------|-------|
| apt error handling | `apt update && apt upgrade -y` (silent fail) | `\|\| record_failure "System update"` |
| sysctl application | `sysctl -p` (reapplies all settings) | `grep -q` guard + `sysctl -w` targeted apply |
| Section numbering | 8/9 duplicated, inconsistent | 8=Optional Extras, 9=Final Cleanup, 10=Verification |

---

## Reviewer Feedback

### sourcery-ai Bot

**Comments:**

1. Subshell around notes Git initialization no longer propagates failures into `check_error`; suggested `(...) || check_error "Git initialization"`.
2. `oh_my_zsh_install_script=$(mktemp)` used without checking for failure; suggested validating `mktemp` succeeded.

**Reviewer's Guide** — Provided a flow diagram of the updated Optional Extras → Final Cleanup → Verification sections.

### gemini-code-assist Bot

**4 inline comments:**

| Line(s) | Severity | Issue | Suggestion |
|----------|----------|-------|------------|
| +250-251 | High | `check_error` checks `chown` exit status, not subshell — git init failures silently ignored | Chain with `&&`: `) && chown -R ...` |
| +393-400 | High | Root ownership on CTF/tools dirs; cache glob misses dotfiles | Add `chown -R` in cleanup; `rm -rf` the `.cache` dir itself instead of globbing |
| +305-306 | Medium | Appending to `/etc/sysctl.conf` is fragile; existing values with different values won't update | Use `/etc/sysctl.d/99-ctf.conf` drop-in |
| ufw enable | Medium | `yes \| ufw enable` works but `ufw --force enable` is more idiomatic | Use `ufw --force enable` |

### qodo-code-review Bot

**3 bugs identified:**

| # | Severity | Issue | Suggested Fix |
|---|----------|-------|---------------|
| 1 | Bug (Reliability) | Git init errors ignored — `check_error` runs after `chown`, not after subshell | Capture subshell exit status before `chown`, or chain with `&&` |
| 2 | Bug (Security) | Unvalidated sudoers username — `TARGET_USER` only blocks `/`, allows whitespace/special chars | Require `^[a-z_][a-z0-9_-]*$` regex; validate with `visudo -c -f` |
| 3 | Bug (Reliability) | Pip failure not detected — two pip commands before single `check_error` | Add `|| record_failure` to each pip command individually |

### Codacy

- **Status**: Not up to standards
- **Issues**: 1 high (ErrorProne category)

---

## Files Changed

| File | Changes |
|------|---------|
| `install.sh` | +27 / -37 |

---

## Follow-Up Items (from reviewers)

1. **Propagate subshell failures**: Use `(...) || check_error` or chain with `&&` so git init errors aren't masked by subsequent `chown`.
2. **Validate sudoers username**: Restrict `TARGET_USER` to safe username regex (`^[a-z_][a-z0-9_-]*$`); validate with `visudo -c -f`.
3. **Per-pip error handling**: Add `|| record_failure` to each pip command so upgrade failures aren't masked by successful package installs.
4. **Use `/etc/sysctl.d/`**: Drop-in file instead of appending to `/etc/sysctl.conf` for cleaner idempotency.
5. **`ufw --force enable`**: More idiomatic than `yes | ufw enable` for non-interactive environments.
6. **Cache cleanup**: Delete `.cache` directory itself rather than globbing inside it (misses dotfiles).
7. **Chown CTF/tools in cleanup**: Ensure target user owns all created directories, not just notes.
