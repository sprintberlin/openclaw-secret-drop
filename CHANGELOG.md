# Changelog

All notable changes to this project are documented here.

## Unreleased

- Recheck destination files with `lstat` immediately before atomic replacement.
- Reject mixed public/private DNS answers and normalize IPv4-mapped IPv6 addresses.
- Redact provider tokens embedded in `/p/` and `/g/` URL paths.
- Support bare `python -m unittest discover` from the repository root.
- Add optional `--restart-gateway` using OpenClaw's safe restart command.

## 0.1.0 - 2026-09-18

- Add the public `secret-drop` OpenClaw skill.
- Add native Password Pusher retrieval for hosted and self-hosted instances.
- Add native SnapPwd AES-GCM decryption.
- Add atomic `openclaw-env`, `dotenv`, raw-file, and OpenClaw-store destinations.
- Add HTTPS-only fetches, redirect checks, private-address rejection, bounded responses, and secret-free errors.
- Add unit tests, CI, security documentation, and OpenClaw `extraDirs` installation guidance.
