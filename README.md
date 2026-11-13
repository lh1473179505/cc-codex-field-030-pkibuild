# pkibuild

A certification-path builder for a JSON stand-in of X.509, including name constraints, path length, EKU, and CRLs.

`python -m pkibuild inspect --bundle fixtures/bundles/good-chain.json` already lists certificates and checks HMAC well-formedness. `build` is still a stub: a valid HMAC is not enough to trust a leaf.

Standard library only. No Docker, no cryptography package, no openssl command.
