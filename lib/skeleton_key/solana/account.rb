# frozen_string_literal: true

module SkeletonKey
  module Solana
    class Account
      include Support
      include Derivation::SLIP10

      attr_reader :purpose, :coin_type, :account_index, :derived

      DEFAULT_PURPOSE = 44
      SOLANA_COIN = 501
      LEGACY_CHANGELESS_PURPOSE = 44

      def initialize(seed:, purpose: DEFAULT_PURPOSE, coin_type: SOLANA_COIN, account_index: 0)
        @purpose = purpose
        @coin_type = coin_type
        @account_index = account_index
        @derived = derive_from_seed(seed, purpose: purpose, coin_type: coin_type, account: account_index)
      end

      def path
        derived[:path_prefix]
      end

      def address(change: 0, index: nil)
        key_seed, chain_code = derived[:key_seed], derived[:chain_code]
        current_path = path

        unless change.nil?
          current_path = "#{current_path}/#{change}'"
          key_seed, chain_code = ckd_priv(key_seed, chain_code, hardened(change))
        end

        unless index.nil?
          current_path = "#{current_path}/#{index}'"
          key_seed, chain_code = ckd_priv(key_seed, chain_code, hardened(index))
        end

        private_key, public_key = keypair_from_seed(key_seed)

        {
          path: current_path,
          private_key: private_key.unpack1("H*"),
          public_key: public_key.unpack1("H*"),
          address: to_address(public_key),
          chain_code: chain_code
        }
      end

      private

      def derive_from_seed(seed_bytes, purpose:, coin_type:, account:)
        raise Errors::UnsupportedPurposeError.new(purpose) unless purpose == 44
        raise Errors::UnsupportedPurposeError.new(coin_type) unless coin_type == SOLANA_COIN

        key_seed, chain_code = master_from_seed(seed_bytes)
        [
          hardened(purpose),
          hardened(coin_type),
          hardened(account)
        ].each do |index|
          key_seed, chain_code = ckd_priv(key_seed, chain_code, index)
        end

        {
          path_prefix: "m/#{purpose}'/#{coin_type}'/#{account}'",
          key_seed: key_seed,
          chain_code: chain_code
        }
      end

      def hardened(index)
        index | Derivation::SLIP10::HARDENED_FLAG
      end
    end
  end
end
