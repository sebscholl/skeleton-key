# frozen_string_literal: true

require "json"
require "open3"
require "shellwords"
require "tmpdir"

module SolanaDeepFixtureGenerator
  module_function

  ROOT = File.expand_path("..", __dir__)
  SOURCE_FIXTURE = File.join(ROOT, "spec/fixtures/vectors/solana/bip44_standard_golden_master.json")
  OUTPUT_FIXTURE = File.join(ROOT, "spec/fixtures/vectors/solana/bip44_deep_golden_master.json")

  def run
    input = load_input
    rows = deep_paths(input.fetch("account_index")).map do |path|
      derive_path(input.fetch("bip39_mnemonic"), path)
    end

    payload = {
      "coin" => "solana",
      "spec" => "bip44_deep",
      "bip39_mnemonic" => input.fetch("bip39_mnemonic"),
      "bip39_seed" => input.fetch("bip39_seed"),
      "bip32_root_key" => input.fetch("bip32_root_key"),
      "purpose" => input.fetch("purpose"),
      "coin_type" => input.fetch("coin_type"),
      "branches" => group_rows(rows)
    }

    File.write(OUTPUT_FIXTURE, JSON.pretty_generate(payload) + "\n")
  end

  def load_input
    payload = JSON.load_file(SOURCE_FIXTURE)

    {
      "bip39_mnemonic" => payload.fetch("bip39_mnemonic"),
      "bip39_seed" => payload.fetch("bip39_seed"),
      "bip32_root_key" => payload.fetch("bip32_root_key"),
      "purpose" => payload.fetch("purpose"),
      "coin_type" => payload.fetch("coin_type"),
      "account_index" => 0
    }
  end

  def deep_paths(account_index)
    varying_index_paths = (0..19).map do |idx|
      "m/44'/501'/#{account_index}'/0'/#{idx}'"
    end

    varying_change_paths = (0..19).map do |idx|
      "m/44'/501'/#{account_index}'/#{idx}'/20'"
    end

    varying_account_paths = (0..19).map do |idx|
      "m/44'/501'/#{idx}'/21'/20'"
    end

    varying_index_paths + varying_change_paths + varying_account_paths
  end

  def derive_path(mnemonic, path)
    Dir.mktmpdir("solana-deep-fixture") do |dir|
      outfile = File.join(dir, "keypair.json")
      recover_command = Shellwords.join([
        "solana-keygen",
        "recover",
        "prompt://?full-path=#{path}",
        "--outfile", outfile,
        "--force",
        "--skip-seed-phrase-validation"
      ])

      stdin_data = [mnemonic, "", "y"].join("\n") + "\n"
      _stdout, stderr, status = Open3.capture3(
        "script", "-qefc", recover_command, "/dev/null",
        stdin_data: stdin_data
      )
      raise "solana-keygen recover failed for #{path}: #{stderr}" unless status.success?

      keypair = JSON.parse(File.read(outfile))
      private_seed = keypair[0, 32].pack("C*")
      public_key = keypair[32, 32].pack("C*")
      address_stdout, address_stderr, address_status = Open3.capture3("solana-keygen", "pubkey", outfile)
      raise "solana-keygen pubkey failed for #{path}: #{address_stderr}" unless address_status.success?

      {
        "path" => path,
        "address" => address_stdout.strip,
        "public_key" => public_key.unpack1("H*"),
        "private_key" => private_seed.unpack1("H*")
      }
    end
  end

  def group_rows(rows)
    rows.group_by do |row|
      path_parts = row.fetch("path").split("/")
      {
        "bip32_derivation_path" => path_parts[0..-2].join("/"),
        "account_index" => path_parts[3].delete("'").to_i,
        "branch_index" => path_parts[4].delete("'").to_i
      }
    end.map do |metadata, grouped_rows|
      {
        "section" => metadata.fetch("bip32_derivation_path").tr("'", ""),
        "bip32_derivation_path" => metadata.fetch("bip32_derivation_path"),
        "account_index" => metadata.fetch("account_index"),
        "branch_index" => metadata.fetch("branch_index"),
        "addresses" => grouped_rows
      }
    end.sort_by { |branch| [branch.fetch("account_index"), branch.fetch("branch_index")] }
  end
end

if $PROGRAM_NAME == __FILE__
  SolanaDeepFixtureGenerator.run
end
