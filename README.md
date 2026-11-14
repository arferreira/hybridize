# hybridize

Policy-aware post-quantum TLS migration assistant.

hybridize helps teams move from classical key exchange to post-quantum or hybrid configurations without rewriting everything at once. It focuses on finding how cryptography is actually configured in a codebase, and on small, low-risk changes that developers can review and merge. The same finding can lead to different recommendations depending on the target policy: general/commercial systems, CNSA 2.0, or the timelines in Executive Order 14412.

## Status

Early development. The CLI is scaffolded, but none of the commands are implemented yet.

The first target is one high-leverage rule family: explicit TLS curve or group lists in Go and OpenSSL/nginx configurations. These lists override newer runtime defaults and silently turn off post-quantum key exchange.

## What it will do

- Detect places where TLS key exchange groups are configured explicitly.
- Recognize that many of these lists predate post-quantum groups and now opt out of the new defaults.
- Take the runtime version into account (Go version in `go.mod`, OpenSSL version), since the right fix depends on it.
- Produce recommendations and patches that depend on the policy.
- Verify results with a real TLS handshake when possible.

## Example

Given a Go server that pins its curves:

```go
cfg := &tls.Config{
    CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
}
```

the same finding gives different plans for different policies (illustrative output, not implemented yet):

```console
$ hybridize plan . --policy general
server.go:12  CurvePreferences pins classical groups only, disabling X25519MLKEM768
  go.mod: go 1.22, so the default post-quantum group is not available yet
  recommend: bump to go 1.24+, then remove CurvePreferences to use the runtime defaults
  alternative: keep an explicit list with tls.X25519MLKEM768 first

$ hybridize plan . --policy cnsa2
server.go:12  CurvePreferences pins classical groups only
  recommend: an ML-KEM-1024 group (tls.SecP384r1MLKEM1024, or tls.MLKEM1024 on newer Go)
             from a FIPS-validated module; X25519MLKEM768 does not meet CNSA 2.0
```

## What it deliberately does not do

- It does not ship its own implementations of ML-KEM, ML-DSA, or other post-quantum primitives. It builds on existing libraries and, where required, FIPS-validated modules.
- It does not present classical hygiene (replacing MD5 or SHA-1) as post-quantum work.
- It does not try to automatically rewrite complex protocol logic or data formats.
- It does not guess. When a curve list cannot be resolved (an environment variable, a deep call chain, reflection, and so on), it reports the finding as unresolved instead of generating a patch.

## Why it matters

According to [NSA's CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) (version 2.1, December 2024), CNSSP 15 requires all new National Security System acquisitions to be CNSA 2.0 compliant by January 1, 2027, unless otherwise noted. [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks) (June 22, 2026; 91 FR 38483) sets deadlines for federal high-value assets and high-impact systems: post-quantum key establishment by December 31, 2030, and post-quantum signatures by December 31, 2031. The order also directs the FAR Council to propose a rule requiring covered contractors to comply with NIST FIPS, including the PQC algorithms, by December 31, 2030.

With current Go and OpenSSL, the practical work often isn't adding new post-quantum code. It's removing or updating old explicit pins that silently disable the post-quantum groups newer runtimes turn on by default. A naive patch can also break older OpenSSL versions that reject unknown group names. hybridize exists to get that right.

## Current focus

1. Measure how often real Go and nginx/OpenSSL configurations opt out of post-quantum key exchange by accident.
2. Build the smallest correct analyzer and patcher for that rule family.
3. Open real, reviewable pull requests on open-source projects.
4. Keep detection deliberately limited (the current function plus one level of calls in the same package) and treat unresolved values as a first-class result.

## Building

Requires Rust 1.100 or newer.

```sh
cargo build --release
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
