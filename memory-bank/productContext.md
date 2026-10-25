# productContext

## Reviewed intent: membership-versus-trust

Joining a room does not grant readability. Mutual node trust is separate from membership; Computer pairing applies managed-node trust policy without joining rooms. Verify actual bidirectional post/read behavior rather than inferring success from enrollment.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Membership, trust and readability are separate"`.
Evidence: [README.md](../README.md).

## Reviewed intent: anchors-are-bridges

An anchor introduces hosts that cannot otherwise find each other. Directly reachable peers, including peers on the same LAN, must be able to create and join rooms without an anchor.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Direct communication does not require an anchor"`.
Evidence: [README.md](../README.md).
