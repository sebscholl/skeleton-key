# frozen_string_literal: true

require "json"

RSpec.describe "Solana CLI Default Vector Compliance" do
  let(:vectors) { load_fixture("vectors/solana/cli_default_golden_master") }

  describe "Address Derivation" do
    it "matches Solana CLI default no-path key recovery for each fixture mnemonic" do
      vectors.fetch("vectors").each do |vector|
        keyring = SkeletonKey::Keyring.new(
          seed: vector.fetch("bip39_mnemonic"),
          passphrase: vector.fetch("bip39_passphrase")
        )
        solana_account = keyring.solana(derivation_path: nil)
        derived = solana_account.address

        aggregate_failures("for #{vector.fetch('address')}") do
          expect(derived[:path]).to eq(vector["path"])
          expect(derived[:private_key]).to eq(vector.fetch("private_key"))
          expect(derived[:public_key]).to eq(vector.fetch("public_key"))
          expect(derived[:address]).to eq(vector.fetch("address"))
          expect(derived[:chain_code]).to be_nil
        end
      end
    end
  end
end
