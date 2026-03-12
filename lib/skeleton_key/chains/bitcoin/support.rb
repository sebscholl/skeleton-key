# frozen_string_literal: true

module SkeletonKey
  module Chains
    module Bitcoin
      module Support
        extend Utils::Hashing
        extend Utils::Encoding
        include Versioning
        include Paths
        include Outputs

        module_function

        def to_wif(priv_bytes, compressed: true, network: :mainnet)
          prefix = (network == :mainnet ? "\x80".b : "\xEF".b)
          payload = prefix + priv_bytes.b
          payload += "\x01".b if compressed
          base58check_encode(payload)
        end

        def to_p2pkh_address(pubkey_bytes, network: :mainnet)
          prefix = (network == :mainnet ? "\x00" : "\x6F")
          payload = prefix + hash160(pubkey_bytes)
          base58check_encode(payload)
        end

        def to_p2sh_p2wpkh_address(pubkey_bytes, network: :mainnet)
          prog = hash160(pubkey_bytes)
          redeem_script = "\x00\x14" + prog
          script_hash = hash160(redeem_script)

          prefix = (network == :mainnet ? "\x05" : "\xC4")
          payload = prefix + script_hash
          base58check_encode(payload)
        end

        def to_bech32_address(pubkey_bytes, hrp: "bc")
          prog = hash160(pubkey_bytes)
          prog5 = Codecs::Bech32.convert_bits(prog.bytes, 8, 5, true)
          data = [0] + prog5

          Codecs::Bech32.encode(hrp, data, Codecs::Bech32::Encoding::BECH32)
        end
      end
    end
  end
end
