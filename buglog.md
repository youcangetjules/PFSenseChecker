# Bug log

Every bug seen is recorded here. Newest id first. Status is `open` or `fixed`.
Do not put passwords, hashes, tokens, or key material in this file.

| ID | Status | Found | Area | Summary |
|----|--------|-------|------|---------|
| BUG-016 | open | 2026-10-18 | Tooling | Snyk Code is not enabled for the Snyk org, so a code scan of new first-party files cannot run until it is turned on. |
| BUG-015 | open | 2026-09-25 | Login | Sign-in as `julian` shows “Invalid username or password” when the password field has text. Seen again 2026-10-18. Not the same fault as Enter activating 1Password (BUG-014). Cause not confirmed: stored secret does not match, or the public-key pepper used at hash time differs from the pepper used at verify time. |
| BUG-014 | fixed | 2026-10-18 | Login | Enter in the password field activated the 1Password button. In a dialog, Qt treats the next auto-default button in the focus chain as the Enter target, and 1Password sits beside the password field. Fixed in 1.3.56: only Login is the default button. |
| BUG-013 | fixed | 2026-10-18 | 1Password | Fill was still broken after 1.3.48–1.3.50. `op whoami` returned “account is not signed in” (CLI 2.39.0). The wait ran on the UI thread, so the login window froze for up to 90s, and a non-“not found” `item get` failure was shown as “No NetCheck login found”. The CLI was also started with `SW_HIDE`, which can hide its approval window. Fixed in 1.3.56: fill runs off the UI thread, real CLI errors are shown and logged, and `op` is not started hidden. The account still has to be unlocked in the 1Password app. |
| BUG-012 | fixed | 2026-10-18 | Console | Log lines were only on Home → Console, and the pop-out existed only after that page was opened. Fixed in 1.3.57: a companion console window opens with the app and follows the log. |
| BUG-011 | fixed | 2026-10-18 | Login | Help, Options, Forgot Credentials, Login, and Cancel were not on one baseline. Fixed in 1.3.54. |
| BUG-010 | fixed | 2026-10-18 | Login | Login did not highlight on hover. Fixed in 1.3.54. |
| BUG-009 | fixed | 2026-10-18 | Config Check | Explorer drag onto the dashed area showed a stop cursor. During the drag, Windows exposes `FileNameW`, not `text/uri-list`, so a URL-only accept refused the drop. An elevated window also could not take an OLE drop from unelevated Explorer. Fixed in 1.3.52. |
| BUG-008 | fixed | 2026-09-25 | 1Password | CLI returned “account is not signed in” or could not see the desktop app, and the first attempt aborted. Fixed in 1.3.49–1.3.50 by starting the app and polling until unlock or 90s. See BUG-013 for what that fix left broken. |
| BUG-007 | fixed | 2026-08-26 | Config pull | `sudo` hung on OpenSSH 10 because the session had no PTY. Fixed in 1.3.45. |
| BUG-006 | fixed | 2026-08-26 | Splash | Splash did not show; the bar slide ran before the event loop. Fixed in 1.3.41. |
| BUG-005 | fixed | 2026-08-25 | Startup | Emptied core modules (`models`, `discovery`, `viz`, `samples`) made the GUI exit immediately. Fixed in 1.3.33. |
| BUG-004 | fixed | 2026-08-25 | Syslog | Binding a CIDR such as `222.10.50.0/24` raised `getaddrinfo` 11001. Fixed in 1.3.32 by binding `0.0.0.0` and keeping the CIDR as an accept filter. |
| BUG-003 | fixed | 2026-08-25 | Config pull | Remote `cat` of `config.xml` was broken (shell redirection) and the SSH user often could not read the file. Fixed in 1.3.26 and the sudo follow-ups (1.3.29). |
| BUG-002 | fixed | 2026-08-25 | Main window | Status bar was clipped when the window was maximized (`setGeometry(availableGeometry)`). Fixed in 1.3.9. |
| BUG-001 | fixed | 2026-08-25 | Login | Login page crashed silently: `NameError` because `STATUS_BAR_TEXT` was not imported. Fixed in 1.3.1. |
