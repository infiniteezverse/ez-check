# Web surface: design constraints

The original pitch for the browser side was a script that silently records pointer kinematics, timing jitter,
and a hidden WebGL canvas hash, so that "the user notices nothing." That version is out of scope for this repo:

- Canvas/WebGL hashes plus behavioural timing are device fingerprinting. Under GDPR/ePrivacy, and increasingly US
  state privacy laws, that needs disclosure and, in the EU, prior consent. "No PII" doesn't hold: a stable
  fingerprint is an identifier.
- A check that is invisible to the person being checked can't be contested, audited, or declined by them.

Directions that fit the rest of EZ CHECK:

1. **Passkey-first sign-up/checkout.** The same WebAuthn machinery as the agent gate. Strong proof that a real
   device holder is present, and it's a single native prompt the user understands.
2. **Disclosed risk scoring.** If behavioural signals are used, they're named in the site's privacy notice,
   gated on consent where required, scored per session only (no cross-site identifier), and backed by a visible
   fallback (passkey or other challenge) when the score is uncertain.
3. **Server-side signals without fingerprinting.** Rate limits, request-pattern anomalies, and proof-of-work
   challenges that cost bots more than people.
