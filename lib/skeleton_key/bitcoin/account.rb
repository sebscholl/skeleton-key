# frozen_string_literal: true

require_relative "../derivation/bip32"

module SkeletonKey
  module Bitcoin
    # Represents a Bitcoin HD account node derived via BIP32/BIP84.
    #
    # Handles derivation of xprv/xpub for a given account path.
    #
    # @example Default mainnet account
    #   acct = SkeletonKey::Bitcoin::Account.new(seed: seed.bytes)
    #   acct.xprv # => "xprv..."
    #   acct.xpub # => "xpub..."
    #
    class Account
      include Support
      include Derivation::BIP32

      attr_reader :purpose, :coin_type, :account_index, :network, :derived

      DEFAULT_PURPOSE = 84   # BIP84 = native SegWit
      MAINNET_COIN    = 0
      TESTNET_COIN    = 1

      # @param seed [String] raw seed bytes
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @param coin_type [Integer] 0 = mainnet, 1 = testnet
      # @param account_index [Integer] account number (hardened)
      # @param network [:mainnet, :testnet]
      def initialize(
        seed:,
        purpose: DEFAULT_PURPOSE,
        coin_type: MAINNET_COIN,
        account_index: 0,
        network: :mainnet
      )
        @purpose       = purpose
        @coin_type     = coin_type
        @account_index = account_index
        @network       = network

        @derived = derive_from_seed(
          seed,
          purpose: purpose,
          coin_type: coin_type,
          account: account_index
        )
      end

      # @return [String] BIP32 extended private key (xprv, zprv if re-encoded)
      def xprv
        @derived[:xprv]
      end

      # @return [String] BIP32 extended public key (xpub, zpub if re-encoded)
      def xpub
        @derived[:xpub]
      end

      # @return [String] BIP32 path
      def path
        "m/#{purpose}'/#{coin_type}'/#{account_index}'"
      end

      private

      # Derives an account node details from seed bytes and derivation path components.
      #
      # @param seed_bytes [String] raw seed bytes
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @param coin_type [Integer] 0 = mainnet, 1 = testnet
      # @param account [Integer] account number (hardened)
      # @return [Account] the derived account
      def derive_from_seed(seed_bytes, purpose: 84, coin_type: 0, account: 0)
        k, c = master_from_seed(seed_bytes)
        depth  = 0
        fpr    = "\x00\x00\x00\x00"
        child  = 0

        # purpose'
        child = (0x8000_0000 | purpose)
        k, c = ckd_priv(k, c, child)
        depth += 1
        fpr = fingerprint_from_pubkey(privkey_to_pubkey_compressed(k))

        # coin'
        child = (0x8000_0000 | coin_type)
        k, c = ckd_priv(k, c, child)
        depth += 1
        fpr = fingerprint_from_pubkey(privkey_to_pubkey_compressed(k))

        # account'
        child = (0x8000_0000 | account)
        k, c = ckd_priv(k, c, child)
        depth += 1
        fpr = fingerprint_from_pubkey(privkey_to_pubkey_compressed(k))

        pub = privkey_to_pubkey_compressed(k)

        {
          k_int: k,
          c: c,
          xprv: serialize_xprv(k, c, depth: depth, parent_fpr: fpr, child_num: child),
          xpub: serialize_xpub(pub, c, depth: depth, parent_fpr: fpr, child_num: child)
        }
      end
    end
  end
end
