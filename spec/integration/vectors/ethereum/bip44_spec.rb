# frozen_string_literal: true

require "json"

RSpec.describe "Ethereum BIP44 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/ethereum/bip44_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:ethereum_account) { keyring.ethereum(purpose: 44, coin_type: 60, account_index: 0) }

  describe "Account Extended Keys" do
    it "derives the correct extended account private key" do
      expect(ethereum_account.derived[:account_extended_private_key]).to eq(vectors["account_extended_private_key"])
    end

    it "derives the correct extended account public key" do
      expect(ethereum_account.derived[:account_extended_public_key]).to eq(vectors["account_extended_public_key"])
    end
  end

  describe "BIP32 Root Extended Keys" do
    it "derives the correct BIP32 branch extended private key" do
      expect(ethereum_account.derived[:branch_extended_private_key]).to eq(vectors["branch_extended_private_key"])
    end

    it "derives the correct BIP32 branch extended public key" do
      expect(ethereum_account.derived[:branch_extended_public_key]).to eq(vectors["branch_extended_public_key"])
    end
  end

  describe "Address Derivation" do
    it "derives the expected Ethereum addresses and keys" do
      vectors["addresses"].each do |addr|
        path_parts = addr["path"].split("/")
        change = path_parts[-2].to_i
        index = path_parts[-1].to_i

        derived = ethereum_account.address(change: change, index: index)

        aggregate_failures("for #{addr['path']}") do
          expect(derived[:path]).to eq(addr["path"])
          expect(derived[:private_key]).to eq(addr["private_key"])
          expect(derived[:public_key]).to eq(addr["public_key"])
          expect(derived[:address]).to eq(addr["address"])
        end
      end
    end
  end
end
