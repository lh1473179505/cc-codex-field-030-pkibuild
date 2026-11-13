# Build rules

Reuse `load_bundle`, `tbs_bytes`, and `check_sig`. Signatures in this lab are HMAC-SHA256 over the canonical TBS (see `tbs_bytes`) with a key from `bundle.raw.keys` named by `sig_key`. This is a stand-in for public-key signatures so the task can stay in the standard library. A correct HMAC does **not** by itself mean the certificate is trusted.

## Path construction

Find a certificate in `certs` or `trust_anchors` whose `serial` equals `--leaf`. Missing leaf is `unknown_leaf`.

Build a chain `leaf, ..., anchor` such that:

- The last certificate is one of `trust_anchors` (compared by `ski`). Using a certificate that only appears in `certs` as if it were an anchor is `untrusted_root`.
- For each adjacent pair (issued, issuer_cert): `issued.issuer` equals `issuer_cert.subject` (all of cn, org, ou, country), and `issued.aki` equals `issuer_cert.ski`. If multiple candidates share that subject/ski, you must try them; do not stop at the first expired or revoked issuer if another candidate would work.
- Each issuer HMAC is checked with `check_sig`. Failure is `bad_signature` for that cert. The leaf is also HMAC-checked with its `sig_key` (usually the issuer's key id).
- `now` must satisfy `not_before <= now < not_after` for every cert (`expired` or `not_yet_valid`).
- Every certificate except the leaf must have `ca: true` and `keyUsage` containing `keyCertSign`. A leaf may not have `keyCertSign` required. Missing `keyCertSign` on a CA is `ku_violation`.
- `path_len` on a CA limits how many *following CA certificates* may appear after it (not counting the CA itself, not counting the leaf). A CA with `path_len: 0` may issue a leaf but not another CA. Violation is `path_len`.
- If `--eku` is set, the leaf must include that EKU or include `anyExtendedKeyUsage`. Intermediate CAs are not required to have it. Failure is `eku_violation`.
- CRLs: each `crls` entry is `{issuer_ski, this_update, next_update, revoked: [serial, ...]}`. It applies when `issuer_ski` equals the issuer of a cert in the path (for the anchor, the CRL issuer is the anchor itself). The CRL is in force if `this_update <= now < next_update` (or `next_update` is omitted). A serial on the list is `revoked`. A missing CRL is not an error; this lab does not require exhaustion, but a *present and in-force* CRL that lists the serial must be honoured. A CRL whose HMAC is in the bundle (`sig_key` / `signature` fields if present) must also check out, otherwise ignore that CRL and add a note `bad_crl` (do not fail the whole path only because a CRL was unreadable, unless that was the only CRL that would have listed the cert — still ignore it).

## Name constraints

Each CA may carry `name_constraints`. They accumulate down the path: a child cannot widen a parent's permitted set, and excluded subtrees of a parent still apply.

- DNS: a permitted DNS name `example.test` allows that name and any label-suffix (`a.example.test`), not `example.test.evil`. A leading dot `.example.test` means only subdomains, not the bare name. Constraints apply to the *leaf* subject CN if it looks like a DNS name (contains a dot) and to every DNS SAN. If the leaf has no DNS SAN and the CN is not a DNS name, DNS constraints are not checked against CN.
- A name in an excluded subtree always fails (`name_constraint`), even if also permitted.
- If a CA introduces a permitted DNS list, the leaf must match at least one permitted name after intersecting with ancestors (intersection of permitted sets: a name must be allowed by every CA that expressed a permitted list).
- IP SANs are checked against `permitted_ip` / `excluded_ip` CIDRs the same way.

## Report

- `decision`, `reason_codes`
- `path`: list of serials from leaf to anchor on allow; on deny, the best attempted path (may be empty)
- `anchor_ski`
- `notes`: optional

If several valid paths exist, pick the shortest, then the one whose anchor ski is lexicographically smallest.

Exit 0 / 1 / 2 as usual. Public `--now` is 1763000000.

## Public fixtures

`--bundle fixtures/bundles/NAME.json --leaf SERIAL`:

- `good-chain.json` leaf `leaf-www` `--eku serverAuth` → allow, path `[leaf-www, int-ca, root-a]`
- `good-chain.json` leaf `leaf-www` `--eku codeSigning` → deny `eku_violation`
- `expired-int.json` leaf `leaf-www` → deny `expired`
- `name-constraint-fail.json` leaf `leaf-evil` → deny `name_constraint` (parent CA permits only `.shop.test`)
- `name-constraint-ok.json` leaf `leaf-ok` → allow
- `pathlen-fail.json` leaf `leaf-www` → deny `path_len`
- `revoked-leaf.json` leaf `leaf-www` → deny `revoked`
- `untrusted.json` leaf `leaf-www` → deny `untrusted_root` (chain ends at a CA that is not a trust anchor)
