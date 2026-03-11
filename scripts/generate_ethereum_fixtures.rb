# frozen_string_literal: true

require "json"
require "fileutils"
require "open3"

module EthereumFixtureGenerator
  module_function

  ROOT = File.expand_path("..", __dir__)
  DEFAULT_INPUT_FILE = File.join(ROOT, "solana-key-test.txt")
  FIXTURE_DIR = File.join(ROOT, "spec/fixtures/vectors/ethereum")
  CAST = File.expand_path("~/.foundry/bin/cast")

  def run(input_file = DEFAULT_INPUT_FILE)
    input = load_input(input_file)
    FileUtils.mkdir_p(FIXTURE_DIR)

    write_fixture(
      "bip32_golden_master.json",
      build_fixture(
        spec: "bip32",
        input: input,
        purpose: 32,
        coin_type: 60,
        account_index: 0,
        paths: bip32_paths
      )
    )

    write_fixture(
      "bip44_golden_master.json",
      build_fixture(
        spec: "bip44",
        input: input,
        purpose: 44,
        coin_type: 60,
        account_index: 0,
        paths: bip44_paths
      )
    )
  end

  def load_input(path)
    data = {}

    File.readlines(path, chomp: true).each do |line|
      next if line.strip.empty?

      key, value = line.split(":", 2)
      next if value.nil?

      data[key.strip] = value.strip
    end

    {
      "mnemonic" => fetch_required(data, "BIP39 Mnemonic", path),
      "bip39_seed" => fetch_required(data, "BIP39 Seed", path),
      "bip32_root_key" => fetch_required(data, "BIP39 Root Key", path)
    }
  end

  def fetch_required(data, key, path)
    value = data[key]
    raise "missing #{key} in #{path}" if value.nil? || value.empty?

    value
  end

  def bip32_paths
    varying_index_paths = (0..19).map { |index| "m/0/#{index}" }
    varying_change_paths = (0..19).map { |change| "m/#{change}/20" }
    varying_index_paths + varying_change_paths
  end

  def bip44_paths
    varying_index_paths = (0..19).map { |index| "m/44'/60'/0'/0/#{index}" }
    varying_change_paths = (0..19).map { |change| "m/44'/60'/0'/#{change}/20" }
    varying_account_paths = (0..19).map { |account| "m/44'/60'/#{account}'/20/20" }
    varying_index_paths + varying_change_paths + varying_account_paths
  end

  def build_fixture(spec:, input:, purpose:, coin_type:, account_index:, paths:)
    {
      "coin" => "ethereum",
      "spec" => spec,
      "mnemonic" => input.fetch("mnemonic"),
      "bip39_seed" => input.fetch("bip39_seed"),
      "bip32_root_key" => input.fetch("bip32_root_key"),
      "purpose" => purpose,
      "coin_type" => coin_type,
      "account_index" => account_index,
      "addresses" => paths.map { |path| derive_path(input.fetch("mnemonic"), path) }
    }
  end

  def derive_path(mnemonic, path)
    private_key = capture!(
      CAST, "wallet", "private-key",
      "--mnemonic", mnemonic,
      "--mnemonic-derivation-path", path
    )

    public_key = capture!(
      CAST, "wallet", "public-key",
      "--private-key", private_key
    )

    address = capture!(
      CAST, "wallet", "address",
      "--private-key", private_key
    )

    {
      "path" => path,
      "private_key" => private_key.delete_prefix("0x"),
      "public_key" => public_key.delete_prefix("0x"),
      "address" => address
    }
  end

  def capture!(*command)
    output, status = Open3.capture2(*command)
    raise "#{command.join(' ')} failed" unless status.success?

    output.strip
  end

  def write_fixture(filename, payload)
    File.write(File.join(FIXTURE_DIR, filename), JSON.pretty_generate(payload) + "\n")
  end
end

if $PROGRAM_NAME == __FILE__
  EthereumFixtureGenerator.run(ARGV[0] || EthereumFixtureGenerator::DEFAULT_INPUT_FILE)
end
