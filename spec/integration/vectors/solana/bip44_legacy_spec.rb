# frozen_string_literal: true

require "json"

RSpec.describe "Solana BIP44 Legacy Vector Compliance" do
  let(:vectors) { load_fixture("vectors/solana/bip44_legacy_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  subject(:solana_account) do
    keyring.solana(
      purpose: vectors["purpose"],
      coin_type: vectors["coin_type"],
      account_index: vectors["account_index"]
    )
  end

  describe "Address Derivation" do
    it "derives the expected legacy Solana addresses and keys" do
      vectors["addresses"].each do |addr|
        account_index = addr["path"].split("/")[3].delete("'").to_i
        derived = keyring.solana(account_index: account_index).address(change: nil, index: nil)

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
