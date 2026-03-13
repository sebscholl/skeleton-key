# SkeletonKey

```
                ██████████████
           ██████▓░░░░░░░░░▓██████
         ███░░░░▓████████████▓░░░░███
        ██░░▓██▓░░░██░░░██░░░▓██▓░░██
       ██░██░░██░░░██░░░██░░░██░░██░██
       ██░██░░██░░░██░░░██░░░██░░██░██
        ██░░▓██▓░░░██░░░██░░░▓██▓░░██
         ███░░░░▓████████████▓░░░░███
           ██████▓░░░░░░░░░▓██████
                ████████████████
                     ██░░██
                     ██░░██        ╔═╗╦╔═╔═╗╦  ╔═╗╔╦╗╔═╗╔╗╔
                     ██░░██        ╚═╗╠╩╗║╣ ║  ║╣  ║ ║ ║║║║
                     ██░░██        ╚═╝╩ ╩╚═╝╩═╝╚═╝ ╩ ╚═╝╝╚╝
                     ██░░██        ╦╔═╔═╗╦ ╦
                     ██░░██        ╠╩╗║╣ ╚╦╝
                     ██░░██        ╩ ╩╚═╝ ╩
                     ██░░██
                     ██░░████      Zero-dependency deterministic wallet
                     ██░░░░██      recovery & key derivation for
                     ██░░████
                     ██░░██
                     ██░░██████
                     ██░░░░░░██
                     ██░░██████
                     ██░░██
                     ██████
```

[![Gem Version](https://badge.fury.io/rb/skeleton_key.svg )](https://badge.fury.io/rb/skeleton_key )
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg )](LICENSE)
[![Ruby](https://img.shields.io/badge/Ruby-%3E%3D%203.2-black )](https://www.ruby-lang.org )
[![Safety-Critical](https://img.shields.io/badge/⚠%20Safety--Critical-black )](SECURITY.md)

SkeletonKey is a Ruby library for deterministic wallet recovery and key derivation across Bitcoin, Ethereum, and Solana. It is designed around a strict boundary:

- recovery formats in the recovery layer
- shared seed and derivation primitives in the shared layer
- chain-specific address and serialization behavior in chain modules

This repository is safety-critical. A small bug in recovery, derivation, encoding, or serialization can produce valid-looking but wrong keys.

## What SkeletonKey Does

SkeletonKey takes a root secret and turns it into chain-specific accounts and addresses:

- generate a new BIP39 mnemonic
- recover a seed from a BIP39 mnemonic
- generate new SLIP-0039 shares
- recover a master secret from SLIP-0039 shares
- normalize raw seeds into a canonical `SkeletonKey::Seed`
- derive Bitcoin, Ethereum, and Solana accounts from one seed
- validate behavior against large golden-master fixture sets

Current supported standards and conventions:

- BIP39 recovery
- SLIP-0039 recovery
- BIP32 secp256k1 derivation
- SLIP-0010 Ed25519 derivation
- Bitcoin BIP32, BIP44, BIP49, BIP84, BIP141
- Ethereum BIP32 and BIP44
- Solana hardened BIP44-style paths

## Installation

```bash
bin/setup
```

Or, if the environment is already prepared:

```bash
bundle install
```

## Developer Quick Start

Open a console with the library loaded:

```bash
bin/console
```

Generate a random keyring:

```ruby
keyring = SkeletonKey::Keyring.new
```

Initialize from an existing hex seed:

```ruby
keyring = SkeletonKey::Keyring.new(
  seed: "13e3e43b779fc6cda3bd9a1e762768dd3e273389adb81787adbe880341609e88"
)
```

Derive default chain accounts:

```ruby
bitcoin  = keyring.bitcoin
ethereum = keyring.ethereum
solana   = keyring.solana
```

## Recovery Experience

### BIP39

Generate a new mnemonic:

```ruby
mnemonic = SkeletonKey::Recovery::Bip39.generate(word_count: 24)

mnemonic.phrase
mnemonic.words
mnemonic.seed
```

Generate deterministically from explicit entropy:

```ruby
mnemonic = SkeletonKey::Recovery::Bip39.generate(
  word_count: 12,
  entropy: ("\x00".b * 16)
)
```

Or convert entropy directly:

```ruby
mnemonic = SkeletonKey::Recovery::Bip39.from_entropy("00000000000000000000000000000000")
```

Use [`SkeletonKey::Recovery::Bip39`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/recovery/bip39.rb) when you want explicit mnemonic validation and seed recovery:

```ruby
bip39 = SkeletonKey::Recovery::Bip39.new(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

seed = bip39.seed
keyring = SkeletonKey::Keyring.new(seed: seed)
```

You can also pass a mnemonic directly to `Seed.import` or `Keyring.new`:

```ruby
seed = SkeletonKey::Seed.import(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

keyring = SkeletonKey::Keyring.new(
  seed: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
```

What BIP39 validation currently enforces:

- official BIP39 word counts only: `12`, `15`, `18`, `21`, `24`
- English wordlist membership
- checksum validation
- PBKDF2 seed reconstruction

### SLIP-0039

Generate a single-group SLIP-0039 share set:

```ruby
share_set = SkeletonKey::Recovery::Slip39.generate(
  master_secret: "00112233445566778899aabbccddeeff",
  member_threshold: 3,
  member_count: 5,
  passphrase: "",
  extendable: true,
  iteration_exponent: 1
)

share_set.mnemonic_groups
share_set.all_shares
share_set.recovery_set
```

Generate a multi-group share set:

```ruby
share_set = SkeletonKey::Recovery::Slip39.generate(
  master_secret: "00112233445566778899aabbccddeeff",
  group_threshold: 2,
  groups: [
    { member_threshold: 2, member_count: 3 },
    { member_threshold: 3, member_count: 5 },
    { member_threshold: 2, member_count: 4 }
  ],
  passphrase: "PASS8",
  extendable: false,
  iteration_exponent: 2
)
```

`master_secret` may be raw bytes, hex, octets, or a `SkeletonKey::Seed`, but SLIP-0039 generation only accepts master-secret lengths of `16`, `24`, or `32` bytes.

Use [`SkeletonKey::Recovery::Slip39`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/recovery/slip39.rb) when recovering from Shamir shares:

```ruby
shares = [
  "share one ...",
  "share two ...",
  "share three ..."
]

seed = SkeletonKey::Recovery::Slip39.recover(shares, passphrase: "")
keyring = SkeletonKey::Keyring.new(seed: seed)
```

Important DX rule: pass a **flat array of share strings**. Do not group them yourself. Group membership is inferred from the metadata encoded inside each share.

Multi-group recovery uses the same interface:

```ruby
shares = [
  group_0_share_0,
  group_0_share_1,
  group_2_share_0,
  group_2_share_1
]

seed = SkeletonKey::Recovery::Slip39.recover(shares, passphrase: "PASS8")
```

Important safety note: `Slip39.recover` validates the share set, but a wrong passphrase is not guaranteed to raise. It can yield a different valid-length secret. If passphrase correctness matters operationally, verify the recovered seed against a known address, fingerprint, or other expected identifier.

## Ruby Secret Handling

SkeletonKey is intentionally a sharp library: the point is to recover and export key material so the caller can hand it to signing, wallet, or custody code. That is useful, but it carries Ruby-specific constraints.

Ruby does not provide hard guarantees for secure memory erasure:

- strings are garbage-collected
- sensitive values may be copied during encoding, packing, or concatenation
- intermediate buffers may exist outside the object you hold

SkeletonKey therefore does not claim guaranteed zeroization. The correct posture is best-effort operational hygiene:

- keep mnemonics, seeds, private keys, and WIFs in scope for as little time as possible
- avoid logging, inspecting, or serializing secret-bearing objects in development tools
- prefer process boundaries and short-lived workers for sensitive workflows
- hand recovered keys directly to downstream signing code instead of caching them in application state
- verify recovered BIP39 or SLIP-0039 material against known addresses or fingerprints before using it operationally

If your threat model requires hard memory guarantees, Ruby is the wrong layer to trust with long-lived secret custody.

## Keyring Experience

[`SkeletonKey::Keyring`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/keyring.rb) is the main developer entry point. It accepts normalized seed material and exposes chain-specific account builders.

```ruby
keyring = SkeletonKey::Keyring.new(seed: seed)

btc = keyring.bitcoin(purpose: 84, coin_type: 0, account_index: 0, network: :mainnet)
eth = keyring.ethereum(purpose: 44, coin_type: 60, account_index: 0)
sol = keyring.solana(account_index: 0)
```

Supported seed input shapes:

- `nil` for a new random seed
- `SkeletonKey::Seed`
- raw bytes
- hex seed string
- array of octets
- BIP39 mnemonic string

### End-to-End Example

This is the simplest full-circle flow for manual testing in `bin/console`:

```ruby
mnemonic = SkeletonKey::Recovery::Bip39.generate(word_count: 12)

puts mnemonic.phrase
puts mnemonic.seed.hex

keyring = SkeletonKey::Keyring.new(seed: mnemonic.seed)

bitcoin = keyring.bitcoin(purpose: 84, coin_type: 0, account_index: 0, network: :mainnet)
ethereum = keyring.ethereum(purpose: 44, coin_type: 60, account_index: 0)
solana = keyring.solana(account_index: 0)

btc_node = bitcoin.address(change: 0, index: 0)
eth_node = ethereum.address(change: 0, index: 0)
sol_node = solana.address(change: 0)

puts btc_node[:path]
puts btc_node[:address]
puts btc_node[:wif]

puts eth_node[:path]
puts eth_node[:address]
puts eth_node[:private_key]

puts sol_node[:path]
puts sol_node[:address]
puts sol_node[:private_key]
```

If you want to verify that the mnemonic alone is sufficient, reconstruct the same keyring from the phrase:

```ruby
phrase = mnemonic.phrase

recovered = SkeletonKey::Keyring.new(seed: phrase)
recovered_btc = recovered.bitcoin(purpose: 84, coin_type: 0, account_index: 0, network: :mainnet)
recovered_eth = recovered.ethereum(purpose: 44, coin_type: 60, account_index: 0)
recovered_sol = recovered.solana(account_index: 0)

expect_btc = recovered_btc.address(change: 0, index: 0)
expect_eth = recovered_eth.address(change: 0, index: 0)
expect_sol = recovered_sol.address(change: 0)

puts expect_btc[:address] == btc_node[:address]
puts expect_eth[:address] == eth_node[:address]
puts expect_sol[:address] == sol_node[:address]
```

All three comparisons should print `true`.

## Bitcoin Experience

Bitcoin accounts are created through [`SkeletonKey::Chains::Bitcoin::Account`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/chains/bitcoin/account.rb).

Examples:

```ruby
account = keyring.bitcoin(purpose: 84, coin_type: 0, account_index: 0, network: :mainnet)

account.xprv
account.xpub
account.path
```

Derive an address:

```ruby
node = account.address(change: 0, index: 0)

node[:path]
node[:address]
node[:wif]
node[:privkey]
node[:pubkey]
```

Derive a branch extended keypair:

```ruby
branch = account.branch_extended_keys(change: 0)

branch[:path]
branch[:xprv]
branch[:xpub]
```

Supported Bitcoin purposes:

- `32`: legacy root-branch BIP32 vectors
- `44`: BIP44 P2PKH
- `49`: BIP49 wrapped SegWit
- `84`: BIP84 native SegWit
- `141`: native SegWit root-branch vectors

## Ethereum Experience

Ethereum accounts are created through [`SkeletonKey::Chains::Ethereum::Account`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/chains/ethereum/account.rb).

```ruby
account = keyring.ethereum(purpose: 44, coin_type: 60, account_index: 0)

account.path
```

Derive an address:

```ruby
node = account.address(change: 0, index: 0)

node[:path]
node[:private_key]          # hex, no 0x
node[:public_key]           # 64-byte uncompressed payload, hex
node[:compressed_public_key]
node[:address]              # EIP-55 checksummed 0x...
```

Derive branch extended keys:

```ruby
branch = account.branch_extended_keys(change: 0)

branch[:path]
branch[:xprv]
branch[:xpub]
```

Supported Ethereum purposes:

- `32`: legacy BIP32 root mode
- `44`: BIP44 `m/44'/60'/account'/change/index`

## Solana Experience

Solana accounts are created through [`SkeletonKey::Chains::Solana::Account`](/home/sebscholl/Code/skeleton-key/lib/skeleton_key/chains/solana/account.rb).

```ruby
account = keyring.solana(account_index: 0)
account.path
```

Derive a wallet-style Solana address:

```ruby
node = account.address(change: 0)

node[:path]
node[:private_key]  # 32-byte private seed, hex
node[:public_key]   # 32-byte Ed25519 public key, hex
node[:address]      # Base58-encoded Solana address
```

Derive deeper hardened children:

```ruby
node = account.address(change: 0, index: 15)
```

Solana in SkeletonKey is hardened-only. There is no supported unhardened child derivation path.

## Architecture

The architectural reference lives in [ARCHITECTURE.md](ARCHITECTURE.md). In short:

- recovery layer:
  - BIP39
  - SLIP-0039
- shared layer:
  - seed normalization
  - entropy
  - BIP32
  - SLIP-0010
  - generic extended-key serialization
- Bitcoin layer:
  - WIF
  - Base58Check
  - Bech32
  - script/address semantics
- Ethereum layer:
  - path conventions
  - Keccak address derivation
  - EIP-55 checksums
- Solana layer:
  - hardened path conventions
  - Ed25519 key generation
  - Base58 address encoding

Rules that matter:

- Bitcoin address logic must not leak into shared derivation code.
- Ethereum must not inherit Bitcoin encodings or Bitcoin-style field naming.
- Solana must not inherit secp256k1 assumptions or Ethereum hashing rules.

## Testing and Validation

Run the full suite:

```bash
bundle exec rspec
```

Run a focused file:

```bash
bundle exec rspec spec/lib/skeleton_key/recovery/slip39_spec.rb
```

Run all integration vectors:

```bash
bundle exec rspec spec/integration/vectors
```

Fixture layout:

- `spec/fixtures/recovery/`: BIP39 and SLIP-0039 recovery goldens
- `spec/fixtures/vectors/bitcoin/`: Bitcoin derivation vectors
- `spec/fixtures/vectors/ethereum/`: Ethereum derivation vectors
- `spec/fixtures/vectors/solana/`: Solana derivation vectors
- `spec/fixtures/codecs/`: Base58/Base58Check/Bech32 codec goldens

The preferred validation model in this repository is external golden-master comparison against established tools and independently generated corpora.

## Fixture Policy

Golden-master fixtures in this repository are frozen validation artifacts, not routine developer outputs.

- do not casually regenerate fixtures as part of ordinary feature work
- treat fixture diffs as safety-critical review items
- when a fixture must change, document the external source and validation reason in the commit or PR
- prefer adding new coverage over rewriting existing canonical corpora

## Repository Layout

Key directories:

- `lib/skeleton_key/recovery/`: BIP39 and SLIP-0039 recovery
- `lib/skeleton_key/derivation/`: BIP32, SLIP-0010, derivation paths
- `lib/skeleton_key/chains/bitcoin/`: Bitcoin account and support logic
- `lib/skeleton_key/chains/ethereum/`: Ethereum account and support logic
- `lib/skeleton_key/chains/solana/`: Solana account and support logic
- `lib/skeleton_key/codecs/`: local Base58, Base58Check, Bech32 codecs
- `spec/lib/`: unit specs
- `spec/integration/`: vector compliance specs
- `spec/support/`: shared spec helpers

## Contributing

Read these first:

- [AGENTS.md](AGENTS.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [DOCUMENTATION_STYLE.md](DOCUMENTATION_STYLE.md)

Before submitting changes:

1. keep the architecture boundary intact
2. add or update golden fixtures when behavior changes
3. add unit and integration coverage
4. run `bundle exec rspec`

If you change recovery, derivation, encoding, key serialization, or address construction, external vector proof is required.
