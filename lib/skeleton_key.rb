# Version
require_relative "skeleton_key/version"

# Main module for SkeletonKey
require_relative "skeleton_key/constants"
require_relative "skeleton_key/errors"

# Utilities
require_relative "skeleton_key/utils/hashing"
require_relative "skeleton_key/utils/encoding"
require_relative "skeleton_key/codecs/base58"
require_relative "skeleton_key/codecs/base58_check"
require_relative "skeleton_key/codecs/bech32"

# Derivation methods
require_relative "skeleton_key/derivation/path"
require_relative "skeleton_key/derivation/bip32"
require_relative "skeleton_key/derivation/slip10"

# Core functionality
require_relative "skeleton_key/core/entropy"
require_relative "skeleton_key/recovery/slip39_support/protocol"
require_relative "skeleton_key/recovery/slip39_support/share"
require_relative "skeleton_key/recovery/slip39_support/bit_packing"
require_relative "skeleton_key/recovery/slip39_support/checksum"
require_relative "skeleton_key/recovery/slip39_support/interpolation"
require_relative "skeleton_key/recovery/slip39_support/cipher"
require_relative "skeleton_key/recovery/slip39_support/encoder"
require_relative "skeleton_key/recovery/slip39_support/generated_set"
require_relative "skeleton_key/recovery/slip39_support/decoder"
require_relative "skeleton_key/recovery/slip39_support/secret_recovery"
require_relative "skeleton_key/recovery/slip39_support/generator"
require_relative "skeleton_key/recovery/slip39"

# Higher-level abstractions
require_relative "skeleton_key/recovery/bip39"
require_relative "skeleton_key/seed"
require_relative "skeleton_key/keyring"

# Canonical chain namespace
require_relative "skeleton_key/chains/bitcoin/support/versioning"
require_relative "skeleton_key/chains/bitcoin/support/paths"
require_relative "skeleton_key/chains/bitcoin/support/outputs"
require_relative "skeleton_key/chains/bitcoin/support"
require_relative "skeleton_key/chains/bitcoin/account_derivation"
require_relative "skeleton_key/chains/bitcoin/account"
require_relative "skeleton_key/chains/ethereum/support"
require_relative "skeleton_key/chains/ethereum/account"
require_relative "skeleton_key/chains/solana/support"
require_relative "skeleton_key/chains/solana/account"

module SkeletonKey
  ##
  # Top-level namespace for the SkeletonKey library.
  #
  # The file load order here reflects the repository architecture:
  # - shared constants and typed errors
  # - shared utilities and codecs
  # - shared derivation primitives
  # - recovery formats and seed normalization
  # - chain-specific account implementations
  class Error < StandardError; end

  # Project root directory
  ROOT = File.expand_path("..", __dir__)
end
