# frozen_string_literal: true

require "json"
require "fileutils"
require "pty"
require "shellwords"
require "tmpdir"

module SolanaFixtureGenerator
  module_function

  ROOT = File.expand_path("..", __dir__)
  INPUT_FILE = File.join(ROOT, "solana-key-test.txt")
  FIXTURE_DIR = File.join(ROOT, "spec/fixtures/vectors/solana")

  def run
    input = load_input
    FileUtils.mkdir_p(FIXTURE_DIR)

    write_fixture(
      "bip44_legacy_golden_master.json",
      build_fixture(
        spec: "bip44_legacy",
        input: input,
        paths: legacy_paths(input.fetch("account_index", 0))
      )
    )

    write_fixture(
      "bip44_standard_golden_master.json",
      build_fixture(
        spec: "bip44_standard",
        input: input,
        paths: standard_paths(input.fetch("account_index", 0))
      )
    )
  end

  def load_input
    data = {}

    File.readlines(INPUT_FILE, chomp: true).each do |line|
      next if line.strip.empty?

      key, value = line.split(":", 2)
      next if value.nil?

      data[key.strip] = value.strip
    end

    {
      "mnemonic" => fetch_required(data, "BIP39 Mnemonic"),
      "bip39_seed" => fetch_required(data, "BIP39 Seed"),
      "bip32_root_key" => fetch_required(data, "BIP39 Root Key"),
      "purpose" => 44,
      "coin_type" => 501,
      "account_index" => 0
    }
  end

  def fetch_required(data, key)
    value = data[key]
    raise "missing #{key} in #{INPUT_FILE}" if value.nil? || value.empty?

    value
  end

  def legacy_paths(account_index)
    (0..19).map do |idx|
      "m/44'/501'/#{idx}'"
    end
  end

  def standard_paths(account_index)
    varying_change_paths = (0..19).map do |idx|
      "m/44'/501'/#{account_index}'/#{idx}'"
    end

    varying_account_paths = (0..19).map do |idx|
      "m/44'/501'/#{idx}'/20'"
    end

    varying_change_paths + varying_account_paths
  end

  def build_fixture(spec:, input:, paths:)
    {
      "coin" => "solana",
      "spec" => spec,
      "mnemonic" => input.fetch("mnemonic"),
      "bip39_seed" => input.fetch("bip39_seed"),
      "bip32_root_key" => input.fetch("bip32_root_key"),
      "purpose" => input.fetch("purpose"),
      "coin_type" => input.fetch("coin_type"),
      "account_index" => input.fetch("account_index"),
      "addresses" => paths.map { |path| derive_path(input.fetch("mnemonic"), path) }
    }
  end

  def derive_path(mnemonic, path)
    Dir.mktmpdir("solana-fixture") do |dir|
      outfile = File.join(dir, "keypair.json")
      prompt_uri = "prompt://?full-path=#{path}"
      escaped_uri = Shellwords.escape(prompt_uri)
      escaped_outfile = Shellwords.escape(outfile)
      command = "solana-keygen recover #{escaped_uri} --outfile #{escaped_outfile}"

      PTY.spawn(command) do |reader, writer, pid|
        interact(writer, reader, mnemonic)
        _, status = Process.wait2(pid)
        raise "solana-keygen failed for #{path}" unless status.success?
      end

      keypair = JSON.parse(File.read(outfile))
      private_seed = keypair[0, 32].pack("C*")
      public_key = keypair[32, 32].pack("C*")
      address = `solana-keygen pubkey #{Shellwords.escape(outfile)}`.strip
      raise "solana-keygen pubkey failed for #{path}" if address.empty?

      {
        "path" => path,
        "address" => address,
        "public_key" => public_key.unpack1("H*"),
        "private_key" => private_seed.unpack1("H*")
      }
    end
  end

  def interact(writer, reader, mnemonic)
    read_until(reader, "[recover] seed phrase:")
    writer.puts(mnemonic)
    read_until(reader, "press ENTER to continue:")
    writer.puts("")
    read_until(reader, "Continue? (y/n):")
    writer.puts("y")
  end

  def read_until(reader, marker)
    buffer = +""

    loop do
      chunk = reader.read_nonblock(1024)
      buffer << chunk
      return buffer if buffer.include?(marker)
    rescue IO::WaitReadable
      IO.select([reader])
      retry
    rescue EOFError
      raise "expected prompt containing #{marker.inspect}, got: #{buffer.inspect}"
    end
  end

  def write_fixture(filename, payload)
    File.write(File.join(FIXTURE_DIR, filename), JSON.pretty_generate(payload) + "\n")
  end
end

if $PROGRAM_NAME == __FILE__
  SolanaFixtureGenerator.run
end
