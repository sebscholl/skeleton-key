# frozen_string_literal: true

require "json"

RSpec.describe "Ethereum BIP44 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/ethereum/bip44_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  describe "Address Derivation" do
    it "derives the expected Ethereum addresses and keys for each branch" do
      fixture_branches(vectors).each do |branch|
        ethereum_account = keyring.ethereum(
          purpose: 44,
          coin_type: 60,
          account_index: branch["account_index"]
        )
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
