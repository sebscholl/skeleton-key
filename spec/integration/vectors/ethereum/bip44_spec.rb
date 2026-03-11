# frozen_string_literal: true

require "json"

RSpec.describe "Ethereum BIP44 Vector Compliance" do
  let(:vectors) { load_fixture("vectors/ethereum/bip44_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  describe "Address Derivation" do
    it "derives the expected Ethereum addresses and keys" do
      vectors["addresses"].each do |addr|
        path_parts = addr["path"].split("/")
        account_index = path_parts[3].delete("'").to_i
        change = path_parts[4].to_i
        index = path_parts[5].to_i

        derived = keyring.ethereum(purpose: 44, coin_type: 60, account_index: account_index)
          .address(change: change, index: index)

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
