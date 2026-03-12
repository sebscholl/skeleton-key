# frozen_string_literal: true

require "json"

RSpec.describe "Solana BIP44 Standard Vector Compliance" do
  let(:vectors) { load_fixture("vectors/solana/bip44_standard_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  describe "Address Derivation" do
    it "derives the expected standard Solana addresses and keys for each branch" do
      fixture_branches(vectors).each do |branch|
        solana_account = keyring.solana(
          purpose: vectors["purpose"],
          coin_type: vectors["coin_type"],
          account_index: branch["account_index"]
        )
        change = branch["branch_index"]

        branch["addresses"].each do |addr|
          derived = solana_account.address(change: change, index: nil)

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
