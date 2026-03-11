# frozen_string_literal: true

require "json"

RSpec.describe "Bitcoin BIP32 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/bitcoin/bip32_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:bitcoin_account) { keyring.bitcoin(purpose: 32) }

  describe "Legacy Account Extended Keys" do
    it "does not expose account-level extended keys for root BIP32 vectors" do
      expect(bitcoin_account.derived[:account_xprv]).to eq("")
      expect(bitcoin_account.derived[:account_xpub]).to eq("")
    end
  end

  describe "BIP32 Root Extended Keys" do
    it "derives the correct BIP32 root extended private key" do
      expect(bitcoin_account.derived[:bip32_xprv]).to eq(vectors["bip32_extended_private_key"])
    end

    it "derives the correct BIP32 root extended public key" do
      expect(bitcoin_account.derived[:bip32_xpub]).to eq(vectors["bip32_extended_public_key"])
    end
  end

  describe "Address Derivation" do
    it "derives the expected addresses and keys from the BIP32 root branch" do
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
