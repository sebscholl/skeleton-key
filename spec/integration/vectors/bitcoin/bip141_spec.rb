# frozen_string_literal: true

require "json"

RSpec.describe "Bitcoin BIP141 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/bitcoin/bip141_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:bitcoin_account) { keyring.bitcoin(purpose: 141) }

  describe "Legacy Account Extended Keys" do
    it "does not expose account-level extended keys for root BIP141 vectors" do
      expect(bitcoin_account.derived[:account_xprv]).to eq("")
      expect(bitcoin_account.derived[:account_xpub]).to eq("")
    end
  end

  describe "BIP141 Root Extended Keys" do
    it "derives the correct extended private key for the external branch" do
      expect(bitcoin_account.derived[:bip32_xprv]).to eq(vectors["bip32_extended_private_key"])
    end

    it "derives the correct extended public key for the external branch" do
      expect(bitcoin_account.derived[:bip32_xpub]).to eq(vectors["bip32_extended_public_key"])
    end
  end

  describe "Address Derivation" do
    it "derives the expected native SegWit addresses and keys from the root branch" do
      vectors["addresses"].each do |addr|
        path_parts = addr["path"].split("/")
        change = path_parts[-2].to_i
        index = path_parts[-1].to_i

        derived = bitcoin_account.address(change: change, index: index)

        aggregate_failures("for #{addr['path']}") do
          expect(derived[:path]).to eq(addr["path"])
          expect(derived[:wif]).to eq(addr["private_key"])
          expect(derived[:address]).to eq(addr["address"])
          expect(derived[:pubkey].unpack1("H*")).to eq(addr["public_key"])
        end
      end
    end
  end
end
