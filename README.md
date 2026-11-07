# Wagon Program

Verifiable source of the **Wagon** on-chain program on Solana.

Wagon lets a creator define a basket of Solana tokens; an investor deposits USDC,
receives shares of that basket, and can withdraw at any time. Self-custody and
100% on-chain: Wagon never holds your funds.

- **Program ID:** `2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA`
- **Toolchain:** Anchor 0.30.1 · built with Agave 4.3.0 (platform-tools v1.57) for SBPF v3

## Verify

This repository is the public source that reproduces the deployed program
binary. Anyone can confirm the on-chain program matches this code with
`solana-verify` 0.5.2:

```bash
solana-verify verify-from-repo \
  -u https://api.mainnet-beta.solana.com \
  --program-id 2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA \
  --library-name wagon \
  --arch v3 \
  https://github.com/juancanero03-hue/wagon-program
```

The build is deterministic (Docker-pinned via `solana-verify build`) and its
executable hash equals the hash of the program deployed on mainnet.
`solana-verify` picks the Agave 4.3.0 build image from `[workspace.metadata.cli]`
in `Cargo.toml`; `--arch v3` is required (without it the build targets SBPF v0
and the hash will not match).

## Notes

- The `mock-jupiter` crate is a localnet-only test stub used by the local test
  suite. It is never deployed to devnet or mainnet.
- This is a source mirror kept in sync with the deployed binary at each program
  upgrade; it contains only the program source needed to reproduce the build.
