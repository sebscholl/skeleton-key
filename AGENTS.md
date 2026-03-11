# Repository Guidelines

> [!WARNING]
> SkeletonKey is safety-critical software. A single defect in derivation, encoding, or key handling can plausibly cause millions of dollars in economic damage. There is no acceptable “mostly correct” implementation.

## Project Structure & Module Organization
Keep the repository layout strict and predictable. Production code belongs under `lib/`, tests under `spec/`, and local developer tooling under `bin/`. New structure should follow the current organization instead of introducing new top-level patterns.

- `lib/skeleton_key/core/`: entropy and core primitives
- `lib/skeleton_key/derivation/`: path parsing and BIP32 derivation logic
- `lib/skeleton_key/bitcoin/`: Bitcoin-specific behavior
- `lib/skeleton_key/ethereum/`: Ethereum-specific behavior
- `lib/skeleton_key/solana/`: Solana-specific behavior
- `lib/skeleton_key/utils/`: tightly scoped shared helpers
- `spec/lib/`: unit specs
- `spec/integration/`: vector and cross-module verification
- `spec/fixtures/`: deterministic fixture data
- `spec/support/`: shared RSpec helpers
- `bin/`: local development scripts

## Architecture Boundary
Keep the abstraction boundary explicit. Recovery code may parse and validate recovery material such as BIP39 mnemonics and SLIP-0039 shares. Shared derivation code may derive key material from normalized seeds and paths, but it must not know how Bitcoin or Ethereum encode addresses or serialize chain-facing keys. Chain modules own chain conventions, address construction, and external encodings. The canonical reference is [`ARCHITECTURE.md`](ARCHITECTURE.md).

- Recovery layer: BIP39 mnemonic validation and seed derivation, SLIP-0039 share validation and master-secret recovery
- Shared derivation layer: entropy, seed validation, path parsing, secp256k1/BIP32 primitives, SLIP-0010 hardened derivation, and generic extended-key serialization
- Bitcoin layer: version bytes, WIF, Base58Check, Bech32, script and UTXO-specific derivation behavior
- Ethereum layer: path conventions such as `m/44'/60'/account'/0/index`, Keccak address derivation, EIP-55 checksum formatting, and Ethereum-facing address APIs
- Solana layer: path conventions such as `m/44'/501'/account'/0'`, Ed25519 key generation, hardened-only derivation, and raw Base58 address encoding
- Rule: never place Bitcoin address or serialization logic in shared derivation code
- Rule: never make Ethereum inherit Bitcoin encodings or Bitcoin-specific field naming conventions
- Rule: never make Solana inherit secp256k1 assumptions, Bitcoin address encodings, or Ethereum address hashing behavior

## Risk Posture
Treat every change as safety-critical. Favor simple, explicit code over clever abstractions, and reject any implementation that cannot be explained line by line, exhaustively tested, and independently validated.

## Build, Test, and Development Commands
Use the existing Bundler and RSpec workflow. Run the full suite before submitting changes, and use targeted commands only when isolating failures during development.

- `bin/setup`: install gems and prepare the local environment
- `bundle exec rspec`: run the full test suite
- `bundle exec rspec spec/lib/skeleton_key/derivation/path_spec.rb`: run a single spec file
- `bundle exec rake`: run the standard gem tasks
- `bin/console`: open IRB with SkeletonKey loaded

## Coding Style & Naming Conventions
Follow the existing Ruby style without exception. Keep code small, explicit, deterministic, and easy to audit. File paths must mirror constants exactly, and dependencies must stay minimal.

- Indentation: two spaces
- Namespace: `SkeletonKey`
- Files and methods: snake_case
- Classes and modules: CamelCase
- Constant-to-file example: `SkeletonKey::Derivation::Path` -> `lib/skeleton_key/derivation/path.rb`
- Preferred style: pure functions, deterministic inputs, standard library first
- Dependency rule: add one only if it materially reduces risk
- Error rule: raise typed errors from `SkeletonKey::Errors`, not ad hoc strings

## Testing Guidelines
This project uses RSpec and requires exhaustive validation for every behavioral change. Unit tests should stay close to the code they cover, while integration coverage should prove compatibility against external reference behavior.

- Framework: RSpec
- Execution behavior: randomized order with `.rspec_status`
- Unit spec location: `spec/lib/`
- Integration and vector spec location: `spec/integration/`
- Fixture location: `spec/fixtures/`
- Spec naming: `_spec.rb`
- Example style: explicit, behavior-focused descriptions

> [!IMPORTANT]
> Preferred validation is golden-master comparison against established industry tools. Generate large HD derivation sets, store fixtures in `spec/fixtures/`, and verify SkeletonKey matches them exactly across deep derivation paths and edge cases.

## Commit & Pull Request Guidelines
Current history is mostly `WIP`; contributors should adopt a stricter standard immediately. Commits must describe behavior changes clearly, and pull requests must show exactly how correctness was validated.

- Commit style: short, imperative subject lines
- Commit example: `Add BIP84 golden vector coverage`
- PR requirement: focused summary
- PR requirement: note API or fixture changes
- PR requirement: link the relevant issue when available
- PR requirement: paste exact test command(s) run
- Extra requirement: changes to derivation, encoding, key material, or serialization need external vector proof

## Security & Configuration Tips
Assume any mishandling of secrets or test data can create real downstream risk. Keep all fixtures synthetic, reproducible, and safe to publish.

- Never commit real secrets, mnemonic phrases, or private test data
- Keep fixtures synthetic, deterministic, and reproducible
- Prefer audited standards, transparent algorithms, and minimal dependencies
