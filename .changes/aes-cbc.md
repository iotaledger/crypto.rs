---
"iota-crypto": minor
---

Bumped crypto dependencies to new recent versions.
Rewritten/simplified AES-CBC with HMAC via SimpleHmac.
API change: encrypt and try_encrypt of Aead trait now return size of ciphertext.
