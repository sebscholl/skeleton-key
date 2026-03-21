# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-03-22

### Added

- Added explicit BIP39 passphrase support to `SkeletonKey::Seed.import` and `SkeletonKey::Keyring.new` when recovering from mnemonic input.
- Added opt-in Solana `derivation_path: nil` support to match the default no-path behavior of `solana-keygen new`.
- Added Solana CLI-backed golden vectors and integration coverage for the no-path derivation mode.
- Added this changelog and included it in the packaged gem files.

### Changed

- Documented that BIP39 passphrases are separate from mnemonic words.
- Documented the Solana default path mode and the opt-in Solana CLI compatibility mode.

[Unreleased]: https://github.com/sebscholl/skeleton-key/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sebscholl/skeleton-key/releases/tag/v0.1.1
