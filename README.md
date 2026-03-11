# SkeletonKey

SkeletonKey is a Ruby library for deterministic wallet derivation with vector-based validation across Bitcoin, Ethereum, and Solana.

## Installation

```bash
bundle install
```

## Current API

The public entry point is `SkeletonKey::Keyring`. Initialize a keyring from a seed, then derive chain-specific accounts from it.

```ruby
keyring = SkeletonKey::Keyring.new(seed: "13e3e43b779fc6cda3bd9a1e762768dd3e273389adb81787adbe880341609e88")

bitcoin_account = keyring.bitcoin(purpose: 84, coin_type: 0, account_index: 0)
ethereum_account = keyring.ethereum(purpose: 44, coin_type: 60, account_index: 0)
solana_account = keyring.solana(account_index: 0)

bitcoin_account.address(change: 0, index: 0)
ethereum_account.address(change: 0, index: 0)
solana_account.address(change: 0)
```

## Architecture Boundary

SkeletonKey separates recovery formats, shared HD wallet primitives, and chain-specific behavior.

- Recovery layer: BIP39 mnemonic validation/seed derivation and SLIP-0039 share recovery
- Shared derivation layer: seed handling, path parsing, secp256k1 math, BIP32 child derivation, SLIP-0010 hardened derivation, and generic extended-key serialization primitives
- Bitcoin layer: version bytes, WIF, Base58Check, Bech32, script-aware address rules, and UTXO-oriented derivation behavior
- Ethereum layer: `m/44'/60'/account'/0/index`, Keccak address derivation, EIP-55 checksum formatting, and Ethereum-facing address APIs
- Solana layer: SLIP-0010 hardened derivation, Ed25519 key generation, and raw Base58 address encoding

Bitcoin serialization or address rules must not leak into shared derivation code. Ethereum must use generic extended-key naming at the API and fixture level rather than Bitcoin-specific shorthand such as `xpub` field names.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [AGENTS.md](AGENTS.md) for contributor-facing rules.

## Validation

This project relies on deterministic golden-master fixtures under `spec/fixtures/vectors/`. Integration specs compare SkeletonKey output against externally generated vectors for:

- Bitcoin BIP32, BIP44, BIP49, BIP84, and BIP141
- Ethereum BIP32 and BIP44
- Solana unit coverage for SLIP-0010 Ed25519 derivation and Base58 address generation

Run the full suite with:

```bash
bundle exec rspec
```
