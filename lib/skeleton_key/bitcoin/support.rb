# lib/skeleton_key/bitcoin/support.rb

module SkeletonKey
  module Bitcoin
    module Support
      extend Utils::Hashing
      extend Utils::Encoding

      # Version bytes for extended keys
      VERSION_BYTES = {
        mainnet: {
          legacy: { xpub: 0x0488B21E, xprv: 0x0488ADE4 },
          bip49:  { ypub: 0x049d7cb2, yprv: 0x049d7878 },
          bip84:  { zpub: 0x04b24746, zprv: 0x04b2430c },
        },
        testnet: {
          legacy: { tpub: 0x043587cf, tprv: 0x04358394 },
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
        prefix = (network == :mainnet ? "\x80" : "\xEF")
        payload = prefix + priv_bytes
        payload += "\x01" if compressed
        Encoding.base58check_encode(payload)
      end

      # Hash160 → base58 P2PKH address
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param network [:mainnet, :testnet] network type
      # @return [String] base58check-encoded P2PKH address
      def to_p2pkh_address(pubkey_bytes, network: :mainnet)
        prefix = (network == :mainnet ? "\x00" : "\x6F")
        payload = prefix + hash160(pubkey_bytes)
        Encoding.base58check_encode(payload)
      end

      # Compressed pubkey → bech32 address (P2WPKH)
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param hrp [String] human-readable part ("bc" for mainnet, "tb" for testnet)
      # @return [String] bech32-encoded P2WPKH address
      def to_bech32_address(pubkey_bytes, hrp: "bc")
        # derive witness program = hash160(pubkey)
        prog = hash160(pubkey_bytes)
        Encoding.bech32_encode(hrp, 0, prog) # assuming you add a bech32 encoder in Encoding
      end


      # Serializes an extended private key (xprv)
      #
      # @param k_int [Integer] private key as integer
      # @param chain_code [String] 32-byte chain code
      # @param depth [Integer] depth in the derivation path
      # @param parent_fpr [String] 4-byte parent fingerprint
      # @param child_num [Integer] child index
      # @return [String] base58check-encoded xprv
      def serialize_xprv(k_int, chain_code, depth:, parent_fpr:, child_num:)
        priv_version = version_byte(network: @network, purpose: @purpose, private: true)
        payload = priv_version +
                  [depth].pack("C") +
                  parent_fpr +
                  ser32(child_num) +
                  chain_code +
                  "\x00" + ser256(k_int)

        base58check_encode(payload)
      end

      # Serializes an extended public key (xpub)
      #
      # @param pubkey_bytes [String] compressed public key (33 bytes)
      # @param chain_code [String] 32-byte chain code
      # @param depth [Integer] depth in the derivation path
      # @param parent_fpr [String] 4-byte parent fingerprint
      # @param child_num [Integer] child index
      # @return [String] base58check-encoded xpub
      def serialize_xpub(pubkey_bytes, chain_code, depth:, parent_fpr:, child_num:)
        pub_version = version_byte(network: @network, purpose: @purpose)
        payload = pub_version +
                  [depth].pack("C") +
                  parent_fpr +
                  ser32(child_num) +
                  chain_code +
                  pubkey_bytes

        base58check_encode(payload)
      end

      # Returns the version bytes for extended keys based on network and purpose
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @param private [Boolean] whether the key is private (true for xprv, false for xpub)
      # @return [Array(Integer, Integer)] [xpub_version, xprv_version]
      def version_byte(network:, purpose:, private: false)
        version = if private
          private_version_byte(network: network, purpose: purpose)
        else
          public_version_byte(network: network, purpose: purpose)
        end

        [version].pack("N")
      end

      private

      # Fetches the version bytes for xpub based on network and purpose
      #
      # @param network [:mainnet, :testnet] network type
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @return [String] 4-byte version bytes for xpub
      def public_version_byte(network:, purpose:)
        case [purpose, network]
        when [44, :mainnet] then VERSION_BYTES[:mainnet][:legacy][:xpub]

        when [44, :testnet] then VERSION_BYTES[:testnet][:legacy][:tpub]
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
        when [44, :mainnet] then VERSION_BYTES[:mainnet][:legacy][:xprv]

        when [44, :testnet] then VERSION_BYTES[:testnet][:legacy][:tprv]
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
