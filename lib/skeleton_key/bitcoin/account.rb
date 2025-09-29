# frozen_string_literal: true

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

      # Derive a child address from this account
      #
      # @param change [Integer] 0 = external, 1 = internal/change
      # @param index [Integer] address index
      # @return [Hash] derived address details (privkey, pubkey, wif, bech32, etc.)
      def address(change: 0, index: 0)
        derive_address_from_account(change: change, index: index)
      end

      private

      # Derives an account node details from seed bytes and derivation path components.
      #
      # @param seed_bytes [String] raw seed bytes
      # @param purpose [Integer] derivation purpose (44, 49, 84)
      # @param coin_type [Integer] 0 = mainnet, 1 = testnet
      # @param account [Integer] account number (hardened)
      # @return [Account] the derived account
      # inside SkeletonKey::Bitcoin::Account
      def derive_from_seed(seed_bytes, purpose: 84, coin_type: 0, account: 0)
        # --- master (m/) ---
        k, c = master_from_seed(seed_bytes)
        parent_pub = privkey_to_pubkey_compressed(k)

        # helper to derive one step and return child + the correct parent_fpr/child_num/depth for SERIALIZING the child
        derive_step = ->(k_in, c_in, depth_in, index) do
          parent_pub = privkey_to_pubkey_compressed(k_in)
          parent_fpr = fingerprint_from_pubkey(parent_pub)
          k_out, c_out = ckd_priv(k_in, c_in, index)
          [k_out, c_out, depth_in + 1, parent_fpr, index]
        end

        depth = 0

        # m/44'
        idx_purpose = 0x8000_0000 | purpose
        k, c, depth, fpr_purpose_parent, child_purpose = derive_step.call(k, c, depth, idx_purpose)

        # m/44'/0'
        idx_coin = 0x8000_0000 | coin_type
        k, c, depth, fpr_coin_parent, child_coin = derive_step.call(k, c, depth, idx_coin)

        # m/44'/0'/account'
        idx_account = 0x8000_0000 | account
        k_acct, c_acct, depth_acct, fpr_acct_parent, child_acct = derive_step.call(k, c, depth, idx_account)
        pub_acct = privkey_to_pubkey_compressed(k_acct)

        # ----- Account extended keys (SLIP-132: x/ y/ z/ depending on purpose) -----
        prv_ver_slip = [private_version_byte(network: network, purpose: purpose)].pack("N")
        pub_ver_slip = [public_version_byte(network: network, purpose: purpose)].pack("N")

        account_xprv = serialize_xprv(
          k_acct, c_acct,
          depth: depth_acct,
          parent_fpr: fpr_acct_parent,
          child_num: child_acct,
          version: prv_ver_slip
        )
        account_xpub = serialize_xpub(
          pub_acct, c_acct,
          depth: depth_acct,
          parent_fpr: fpr_acct_parent,
          child_num: child_acct,
          version: pub_ver_slip
        )

        # ----- “BIP32 Extended Keys” as shown by Ian Coleman at m/44'/coin'/account'/0 -----
        # derive the non-hardened change=0 step
        k_chg0, c_chg0, depth_chg0, fpr_chg0_parent, child_chg0 = derive_step.call(k_acct, c_acct, depth_acct, 0)
        pub_chg0 = privkey_to_pubkey_compressed(k_chg0)

        bip32_xprv = serialize_xprv(
          k_chg0, c_chg0,
          depth: depth_chg0,
          parent_fpr: fpr_chg0_parent,
          child_num: child_chg0,
          version: prv_ver_slip
        )
        bip32_xpub = serialize_xpub(
          pub_chg0, c_chg0,
          depth: depth_chg0,
          parent_fpr: fpr_chg0_parent,
          child_num: child_chg0,
          version: pub_ver_slip
        )

        {
          k_int: k_acct,
          c: c_acct,
          # Ian-Coleman-style “BIP32 Extended Keys” at m/44'/coin'/account'/0
          bip32_xprv: bip32_xprv,
          bip32_xpub: bip32_xpub,
          # Account-level (SLIP-132) keys at m/44'/coin'/account'
          account_xprv: account_xprv,
          account_xpub: account_xpub
        }
      end

    end
  end
end
