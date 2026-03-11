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

# Higher-level abstractions
require_relative "skeleton_key/seed"
require_relative "skeleton_key/keyring"

# Specific account implementations
require_relative "skeleton_key/bitcoin/support"
require_relative "skeleton_key/bitcoin/account"
require_relative "skeleton_key/ethereum/support"
require_relative "skeleton_key/ethereum/account"
require_relative "skeleton_key/solana/support"
require_relative "skeleton_key/solana/account"


module SkeletonKey
  class Error < StandardError; end

  # Project root directory
  ROOT = File.expand_path("..", __dir__)
end
