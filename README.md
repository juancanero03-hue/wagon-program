# Wagon Program

Verifiable source of the **Wagon** on-chain program on Solana.

Wagon lets a creator define a basket of Solana tokens; an investor deposits USDC,
receives shares of that basket, and can withdraw at any time. Self-custody and
100% on-chain: Wagon never holds your funds.

- **Program ID:** `2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA`
- **Toolchain:** Anchor 0.30.1 · Solana 1.18.22

## Verify

This repository is the public source that reproduces the deployed program
binary. Anyone can confirm the on-chain program matches this code:

```bash
solana-verify verify-from-repo \
  -u https://api.mainnet-beta.solana.com \
  --program-id 2kZqCjGfKgVR8dUkv4PCogFsFgN3EoSSNX41HN1cBfBA \
  --library-name wagon \
  https://github.com/OWNER/wagon-program
```

The build is deterministic (Docker-pinned via `solana-verify build`) and its
executable hash equals the hash of the program deployed on mainnet.

## Notes

- The `mock-jupiter` crate is a localnet-only test stub used by the local test
  suite. It is never deployed to devnet or mainnet.
- This is a source mirror kept in sync with the deployed binary at each program
  upgrade; it contains only the program source needed to reproduce the build.
