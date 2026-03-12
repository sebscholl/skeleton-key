# frozen_string_literal: true

require "json"

RSpec.describe "Bitcoin BIP44 Hardened Vector Compliance" do
  let(:vectors) { load_fixture("vectors/bitcoin/bip44_hardened_golden_master") }
  let(:keyring) { SkeletonKey::Keyring.new(seed: vectors["bip39_seed"]) }

  describe "Account Extended Keys" do
    it "derives the correct extended account keys for each hardened branch corpus" do
      fixture_branches(vectors).group_by { |branch| branch["account_index"] }.each do |account_index, branches|
        bitcoin_account = keyring.bitcoin(purpose: 44, account_index: account_index)
        external_branch = branches.find { |branch| branch["branch_index"] == 0 }
        branch_keys = bitcoin_account.branch_extended_keys(change: external_branch["branch_index"])

        aggregate_failures("for account #{account_index}") do
          expect(bitcoin_account.derived[:account_xprv]).to eq(external_branch["account_extended_private_key"])
          expect(bitcoin_account.derived[:account_xpub]).to eq(external_branch["account_extended_public_key"])
          expect(branch_keys[:xprv]).to eq(external_branch["bip32_extended_private_key"])
          expect(branch_keys[:xpub]).to eq(external_branch["bip32_extended_public_key"])
        end
      end
    end
  end

  describe "Address Derivation" do
    it "derives the expected hardened addresses and keys for each account branch" do
      fixture_branches(vectors).each do |branch|
        bitcoin_account = keyring.bitcoin(purpose: 44, account_index: branch["account_index"])
        change = branch["branch_index"]

        branch["addresses"].each do |addr|
          index = addr["path"].split("/").last.delete("'").to_i
          derived = bitcoin_account.address(change: change, index: index, hardened_index: true)

          aggregate_failures("for #{addr['path']}") do
            expect(derived[:wif]).to eq(addr["private_key"])
            expect(derived[:address]).to eq(addr["address"])
            expect(derived[:pubkey].unpack1("H*")).to eq(addr["public_key"])
          end
        end
      end
    end
  end
end
