# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Solana
      ##
      # Solana-specific address helpers.
      #
      # Solana addresses are the raw Ed25519 public key bytes encoded with the
      # Bitcoin-style Base58 alphabet. No hashing or script construction is
      # applied at the address layer.
      module Support
        extend Utils::Encoding

        module_function

        # Encodes a 32-byte Ed25519 public key as a Solana address.
        #
        # @param public_key_bytes [String] 32-byte Ed25519 public key
        # @return [String] Base58-encoded Solana address
        def to_address(public_key_bytes)
          Codecs::Base58.encode(public_key_bytes)
        end
      end
    end
  end
end
