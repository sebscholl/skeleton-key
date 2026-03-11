# lib/skeleton_key/bitcoin/support.rb

module SkeletonKey
  module Bitcoin
    module Support
      extend Utils::Hashing
      extend Utils::Encoding

      # Version bytes for extended keys
      VERSION_BYTES = {
        mainnet: {
          bip44: { xpub: 0x0488B21E, xprv: 0x0488ADE4 },
          bip49:  { ypub: 0x049d7cb2, yprv: 0x049d7878 },
          bip84:  { zpub: 0x04b24746, zprv: 0x04b2430c },
        },
        testnet: {
          bip44: { tpub: 0x043587cf, tprv: 0x04358394 },
          bip49:  { upub: 0x044a5262, uprv: 0x044a4e28 },
          bip84:  { vpub: 0x045f1cf6, vprv: 0x045f18bc },
        }
      }

      module_function

      # Encode private key to WIF
      #
      # @param priv_bytes [String] 32-byte private key
      # @param compressed [Boolean] whether the corresponding pubkey is compressed
      # @param network [:mainnet, :testnet] network type
      # @return [String] WIF-encoded private key
      def to_wif(priv_bytes, compressed: true, network: :mainnet)
        prefix = (network == :mainnet ? "\x80".b : "\xEF".b)
         payload = prefix + priv_bytes.b
        payload += "\x01".b if compressed
        base58check_encode(payload)
      end

      # Hash160 → base58 P2PKH address
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param network [:mainnet, :testnet] network type
      # @return [String] base58check-encoded P2PKH address
      def to_p2pkh_address(pubkey_bytes, network: :mainnet)
        prefix = (network == :mainnet ? "\x00" : "\x6F")
        payload = prefix + hash160(pubkey_bytes)
        base58check_encode(payload)
      end

      # Compressed pubkey → base58 P2SH-P2WPKH address (BIP49)
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param network [:mainnet, :testnet] network type
      # @return [String] base58check-encoded P2SH-P2WPKH address
      def to_p2sh_p2wpkh_address(pubkey_bytes, network: :mainnet)
        prog = hash160(pubkey_bytes)                       # witness program (20B)
        redeem_script = "\x00\x14" + prog                  # OP_0 <20-byte-key-hash>
        script_hash = hash160(redeem_script)

        prefix = (network == :mainnet ? "\x05" : "\xC4")   # 0x05 mainnet, 0xC4 testnet
        payload = prefix + script_hash
        base58check_encode(payload)
      end

      # Compressed pubkey → bech32 address (P2WPKH, BIP84)
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param hrp [String] human-readable prefix ("bc" for mainnet, "tb" for testnet)
      # @return [String] bech32-encoded SegWit address
      #
      # @example Mainnet P2WPKH
      #   pub = privkey_to_pubkey_compressed(priv)
      #   addr = to_bech32_address(pub, hrp: "bc") # => "bc1q..."
      #
      # @example Testnet P2WPKH
      #   addr = to_bech32_address(pub, hrp: "tb") # => "tb1q..."
      def to_bech32_address(pubkey_bytes, hrp: "bc")
        prog = hash160(pubkey_bytes) # 20-byte witness program (P2WPKH)

        prog5 = Bech32.convert_bits(prog.bytes, 8, 5, true)
        # witness version 0 + witness program converted to 5-bit words
        data = [0] + prog5

        Bech32.encode(hrp, data, Bech32::Encoding::BECH32)
      end

      # Returns the version byte for extended keys based on network, purpose, and key type
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @param private [Boolean] whether the key is private (true for xprv, false for xpub)
      # @return [Integer] version byte for the key
      def version_byte(network:, purpose:, private: false)
        version = if private
          private_version_byte(network: network, purpose: purpose)
        else
          public_version_byte(network: network, purpose: purpose)
        end

        [version].pack("N")
      end

      # Returns the version bytes for extended keys based on network and purpose
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @return [Array(Integer, Integer)] [xpub_version, xprv_version]
      def version_bytes(network:, purpose:)
        case [purpose, network]
        when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44]
        when [32, :testnet] then VERSION_BYTES[:testnet][:bip44]
        when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84]
        when [141, :testnet] then VERSION_BYTES[:testnet][:bip84]
        when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44]
        when [44, :testnet] then VERSION_BYTES[:testnet][:bip44]
        when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49]
        when [49, :testnet] then VERSION_BYTES[:testnet][:bip49]
        when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84]
        when [84, :testnet] then VERSION_BYTES[:testnet][:bip84]
        else
          raise "Unsupported purpose/network"
        end
      end

      # Derive a child address from this account
      #
      # @param change [Integer] 0 = external, 1 = internal/change
      # @param index [Integer] address index
      # @return [Hash] derived address details (privkey, pubkey, wif, bech32, etc.)
      def derive_address_from_account(change: 0, index: 0)
        k, c = derived[:k_int], derived[:c]

        # step into change level
        k, c = ckd_priv(k, c, change)
        # step into address index level
        k, c = ckd_priv(k, c, index)

        pub = privkey_to_pubkey_compressed(k)

        address =
          case purpose
          when 32
            to_p2pkh_address(pub, network: network)
          when 141
            to_bech32_address(pub, hrp: network == :mainnet ? "bc" : "tb")
          when 44
            to_p2pkh_address(pub, network: network)      # bip44
          when 49
            to_p2sh_p2wpkh_address(pub, network: network) # Wrapped SegWit
          when 84
            to_bech32_address(pub, hrp: network == :mainnet ? "bc" : "tb") # Native SegWit
          else
            raise "Unsupported purpose: #{purpose}"
          end

        {
          path: legacy_root_branch? ? "m/#{change}/#{index}" : "m/#{purpose}'/#{coin_type}'/#{account_index}'/#{change}/#{index}",
          privkey: k,
          pubkey: pub,
          chain_code: c,
          wif: to_wif(ser256(k), network: network),
          address: address
        }
      end

      private

      # Fetches the version bytes for xpub based on network and purpose
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @return [String] 4-byte version bytes for xpub
      def public_version_byte(network:, purpose:)
        case [purpose, network]
        when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xpub]
        when [32, :testnet] then VERSION_BYTES[:testnet][:bip44][:tpub]
        when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zpub]
        when [141, :testnet] then VERSION_BYTES[:testnet][:bip84][:vpub]
        when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xpub]

        when [44, :testnet] then VERSION_BYTES[:testnet][:bip44][:tpub]
        when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49][:ypub]
        when [49, :testnet] then VERSION_BYTES[:testnet][:bip49][:upub]
        when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zpub]
        when [84, :testnet] then VERSION_BYTES[:testnet][:bip84][:vpub]
        else
          raise "Unsupported purpose/network"
        end
      end

      # Fetches the version bytes for xprv based on network and purpose
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @return [String] 4-byte version bytes for xprv
      def private_version_byte(network:, purpose:)
        case [purpose, network]
        when [32, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xprv]
        when [32, :testnet] then VERSION_BYTES[:testnet][:bip44][:tprv]
        when [141, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zprv]
        when [141, :testnet] then VERSION_BYTES[:testnet][:bip84][:vprv]
        when [44, :mainnet] then VERSION_BYTES[:mainnet][:bip44][:xprv]

        when [44, :testnet] then VERSION_BYTES[:testnet][:bip44][:tprv]
        when [49, :mainnet] then VERSION_BYTES[:mainnet][:bip49][:yprv]
        when [49, :testnet] then VERSION_BYTES[:testnet][:bip49][:uprv]
        when [84, :mainnet] then VERSION_BYTES[:mainnet][:bip84][:zprv]
        when [84, :testnet] then VERSION_BYTES[:testnet][:bip84][:vprv]
        else
          raise "Unsupported purpose/network"
        end
      end
    end
  end
end
