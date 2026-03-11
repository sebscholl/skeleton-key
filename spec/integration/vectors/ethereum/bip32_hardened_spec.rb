# frozen_string_literal: true

require "json"

RSpec.describe "Ethereum BIP32 Hardened Vector Compliance" do
  let(:vectors) { load_fixture("vectors/ethereum/bip32_hardened_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:ethereum_account) { keyring.ethereum(purpose: 32) }

  describe "Branch Extended Keys" do
    it "derives the expected branch keys for each hardened branch corpus" do
      fixture_branches(vectors).each do |branch|
        branch_keys = ethereum_account.branch_extended_keys(change: branch["branch_index"])

        aggregate_failures("for #{branch['bip32_derivation_path']}") do
          expect(branch_keys[:xprv]).to eq(branch["bip32_extended_private_key"])
          expect(branch_keys[:xpub]).to eq(branch["bip32_extended_public_key"])
        end
      end
    end
  end

  describe "Address Derivation" do
    it "derives the expected hardened Ethereum addresses and keys for each root branch" do
      fixture_branches(vectors).each do |branch|
        change = branch["branch_index"]

        branch["addresses"].each do |addr|
          index = addr["path"].split("/").last.delete("'").to_i
          derived = ethereum_account.address(change: change, index: index, hardened_index: true)

          aggregate_failures("for #{addr['path']}") do
            expect(derived[:path]).to eq(addr["path"])
            expect(derived[:private_key]).to eq(addr["private_key"])
            expect(derived[:compressed_public_key]).to eq(addr["compressed_public_key"])
            expect(derived[:address]).to eq(addr["address"])
          end
        end
      end
    end
  end
end
