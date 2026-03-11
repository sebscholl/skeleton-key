# Architecture Boundary

SkeletonKey must keep the shared HD wallet foundation separate from chain-specific behavior. This boundary is a correctness requirement, not a style preference.

## Shared Layer

The shared layer owns only chain-agnostic primitives:

- entropy handling
- mnemonic-to-seed derivation
- seed import and validation
- derivation path parsing
- secp256k1 and BIP32 child-key derivation primitives
- generic BIP32 extended-key serialization primitives

This layer may derive key material from a seed and path, and it may serialize generic BIP32 extended keys. It must not know how any specific blockchain encodes addresses or applies chain-specific version-byte conventions beyond generic extended-key structure.

## Bitcoin Layer

Bitcoin code owns all Bitcoin-specific behavior:

- BIP44, BIP49, BIP84, and BIP141 path conventions
- `xprv`/`xpub`, `ypub`/`zpub`, and Bitcoin-specific version-byte handling
- WIF encoding
- Base58Check and Bech32 address generation
- script-type-dependent address behavior
- change-chain and UTXO-oriented derivation rules

## Ethereum Layer

Ethereum code owns all Ethereum-specific behavior:

- Ethereum path conventions such as `m/44'/60'/account'/0/index`
- uncompressed public-key handling when deriving addresses
- Keccak-based address derivation
- EIP-55 checksum formatting
- Ethereum-facing account/address APIs

Ethereum must not inherit Bitcoin serialization assumptions such as WIF, Base58Check, Bech32, or Bitcoin-specific field naming conventions.

## Testing Implication

Golden-master fixtures should follow the same boundary:

- shared derivation vectors validate shared derivation behavior
- Bitcoin vectors validate Bitcoin serialization and address behavior
- Ethereum vectors validate Ethereum address derivation and checksum behavior

If a fixture proves only Bitcoin script or address semantics, it does not belong in Ethereum coverage.
