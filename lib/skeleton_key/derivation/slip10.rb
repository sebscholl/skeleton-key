# frozen_string_literal: true

require "openssl"

module SkeletonKey
  module Derivation
    module SLIP10
      include Utils::Hashing
      include Utils::Encoding

      HARDENED_FLAG = 0x8000_0000
      ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420"

      module_function

      def master_from_seed(seed_bytes)
        i = hmac_sha512("ed25519 seed", seed_bytes)
        [i.byteslice(0, 32), i.byteslice(32, 32)]
      end

      def ckd_priv(parent_key, parent_chain_code, index)
        raise Errors::UnsupportedDerivationIndexError, "ed25519 SLIP-10 requires hardened indices" if index < HARDENED_FLAG

        data = "\x00".b + parent_key + ser32(index)
        i = hmac_sha512(parent_chain_code, data)
        [i.byteslice(0, 32), i.byteslice(32, 32)]
      end

      def keypair_from_seed(seed)
        key = OpenSSL::PKey.read([ED25519_PKCS8_PREFIX + seed.unpack1("H*")].pack("H*"))
        [key.raw_private_key, key.raw_public_key]
      end
    end
  end
end
