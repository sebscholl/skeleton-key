# frozen_string_literal: true

require "json"

RSpec.describe "Bitcoin BIP84 Vector Compliance" do
  let(:vectors) { load_fixture('vectors/bitcoin/bip84_golden_master') }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors['bip39_seed']) }

  subject(:bitcoin_account)  { keyring.bitcoin(purpose: 84) }

  describe "Account Extended Keys" do
    it "derives the correct extended account private key" do
      expect(bitcoin_account.derived[:account_xprv]).to eq(vectors["account_extended_private_key"])
    end

    it "derives the correct extended account public key" do
      expect(bitcoin_account.derived[:account_xpub]).to eq(vectors["account_extended_public_key"])
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
    it "derives the expected addresses and keys" do
      vectors["addresses"].each do |addr|
        index = addr["path"].split("/").last.to_i

        derived = bitcoin_account.address(change: 0, index: index)

        aggregate_failures("for #{addr['path']}") do
          expect(derived[:wif]).to eq(addr["private_key"])
          expect(derived[:address]).to eq(addr["address"])
          expect(derived[:pubkey].unpack1("H*")).to eq(addr["public_key"])
        end
      end
    end
  end
end
