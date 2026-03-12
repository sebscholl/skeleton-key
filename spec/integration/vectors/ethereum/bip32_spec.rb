# frozen_string_literal: true

require "json"

RSpec.describe "Ethereum BIP32 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/ethereum/bip32_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:ethereum_account) { keyring.ethereum(purpose: 32) }

  describe "Address Derivation" do
    it "derives the expected Ethereum addresses and keys for each root branch" do
      fixture_branches(vectors).each do |branch|
        change = branch["branch_index"]

        branch["addresses"].each do |addr|
          index = addr["path"].split("/").last.to_i
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
end
