# EZ Route

- Read README.md, docs/setup.md, and docs/verification.md before changing behavior.
- Keep macOS integration in Sources/EZSwitch and testable logic in Sources/EZSwitchCore.
- Run ./script/verify-routing.sh --offline. Building with --build-only leaves the installed app running.
- Use the application's normal quit path before replacing a running installation.
- Keep device identifiers, subscriptions, credentials, packet captures, and local logs in ignored private paths.
- The public campus profile uses example addresses. Preserve the distinction between fixtures and real deployment data.
- Preserve bundle identity and preference keys when changing branding.
- Use four spaces in Swift and Python, and two spaces in JavaScript.
