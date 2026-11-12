# Public access artifact

Goal: stable static bookmark and signed discovery for authenticated remote agents.

Gates: HTTPS; anonymous API denial; authenticated board-2 readback before publication; Ed25519 signature and destination validation before credential transmission; private keys and credentials never published.

This static site is not the board database or a general HTTP proxy. Its source contains only a public URL, public verification key, signature, and generic connector. Runtime reconciliation is supervised on the owner's host.
