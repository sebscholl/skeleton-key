# frozen_string_literal: true

require "json"

RSpec.describe "Bitcoin BIP32 Hardened Vector Compliance" do
  let(:vectors) { load_fixture("vectors/bitcoin/bip32_hardened_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:bitcoin_account) { keyring.bitcoin(purpose: 32) }

  let(:external_branch) { fixture_branches(vectors).find { |branch| branch["branch_index"] == 0 } }

  describe "Legacy Account Extended Keys" do
    it "does not expose account-level extended keys for root BIP32 vectors" do
      expect(bitcoin_account.derived[:account_xprv]).to eq("")
      expect(bitcoin_account.derived[:account_xpub]).to eq("")
    end
  end

  describe "BIP32 Root Extended Keys" do
    it "derives the correct BIP32 root extended private key for the external branch" do
      branch_keys = bitcoin_account.branch_extended_keys(change: external_branch["branch_index"])
      expect(branch_keys[:xprv]).to eq(external_branch["bip32_extended_private_key"])
    end

    it "derives the correct BIP32 root extended public key for the external branch" do
      branch_keys = bitcoin_account.branch_extended_keys(change: external_branch["branch_index"])
      expect(branch_keys[:xpub]).to eq(external_branch["bip32_extended_public_key"])
    end
  end

  describe "Address Derivation" do
    it "derives the expected hardened addresses and keys for each root branch" do
      fixture_branches(vectors).each do |branch|
        change = branch["branch_index"]

        branch["addresses"].each do |addr|
          index = addr["path"].split("/").last.delete("'").to_i
          derived = bitcoin_account.address(change: change, index: index, hardened_index: true)

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
end
