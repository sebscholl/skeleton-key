# Gem dependencies
require "base58"
require "bech32"

# Version
require_relative "skeleton_key/version"

# Main module for SkeletonKey
require_relative "skeleton_key/constants"
require_relative "skeleton_key/errors"

# Utilities
require_relative "skeleton_key/utils/hashing"
require_relative "skeleton_key/utils/encoding"

# Derivation methods
require_relative "skeleton_key/derivation/bip32"

# Core functionality
require_relative "skeleton_key/core/entropy"

# Higher-level abstractions
require_relative "skeleton_key/seed"
require_relative "skeleton_key/keyring"

# Specific account implementations
require_relative "skeleton_key/bitcoin/support"
require_relative "skeleton_key/bitcoin/account"


module SkeletonKey
  class Error < StandardError; end

  # Project root directory
  ROOT = File.expand_path("..", __dir__)
end
