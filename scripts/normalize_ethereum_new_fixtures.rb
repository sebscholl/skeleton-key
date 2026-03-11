# frozen_string_literal: true

require "csv"
require "json"

module EthereumNewFixtureNormalizer
  module_function

  ROOT = File.expand_path("..", __dir__)
  FIXTURE_DIR = File.join(ROOT, "spec/fixtures/vectors/ethereum")

  KEY_MAP = {
    "bip32_extened_public_key" => "bip32_extended_public_key",
    "public key" => "compressed_public_key",
    "private key" => "private_key"
  }.freeze

  def run
    %w[bip32 bip44].each do |spec|
      payload = parse_file(File.join(FIXTURE_DIR, "#{spec}_new.md"))
      File.write(
        File.join(FIXTURE_DIR, "#{spec}_hardened_golden_master.json"),
        JSON.pretty_generate(payload) + "\n"
      )
    end
  end

  def parse_file(path)
    lines = File.readlines(path, chomp: true)
    spec = File.basename(path, ".md").sub(/_new\z/, "")

    payload = {
      "coin" => "ethereum",
      "spec" => spec,
      "source" => "ian_coleman",
      "branches" => []
    }

    current_section = nil
    index = 0

    while index < lines.length
      line = lines[index]

      if line.start_with?("## ")
        heading = line.delete_prefix("## ").strip
        current_section =
          if heading == "Root"
            payload
          else
            branch = { "section" => heading }.merge(branch_metadata(spec, heading))
            payload["branches"] << branch
            branch
          end
        index += 1
        next
      end

      if line.start_with?("```csv")
        csv_lines = []
        index += 1

        while index < lines.length && lines[index] != "```"
          csv_lines << lines[index]
          index += 1
        end

        current_section["addresses"] = parse_csv(csv_lines)
        index += 1
        next
      end

      if line.include?(":")
        key, value = line.split(":", 2)
        normalized_key = normalize_key(key)
        current_section[normalized_key] = value.strip unless value.nil? || value.strip.empty?
      end

      index += 1
    end

    payload
  end

  def branch_metadata(spec, heading)
    cleaned = heading.sub(/\s+\(hardened\)\z/, "")
    parts = cleaned.split("/")

    case spec
    when "bip32"
      {
        "bip32_derivation_path" => cleaned,
        "account_index" => nil,
        "branch_index" => parts[1].to_i,
        "hardened_index" => true
      }
    when "bip44"
      {
        "bip32_derivation_path" => cleaned,
        "account_index" => parts[3].delete("'").to_i,
        "branch_index" => parts[4].to_i,
        "hardened_index" => true
      }
    else
      raise ArgumentError, "Unsupported Ethereum fixture spec: #{spec}"
    end
  end

  def parse_csv(lines)
    CSV.parse(lines.join("\n"), headers: true).map do |row|
      row.to_h.each_with_object({}) do |(key, value), normalized|
        normalized_key = normalize_key(key)
        normalized[normalized_key] = normalize_value(normalized_key, value)
      end
    end
  end

  def normalize_key(key)
    raw = key.strip
    KEY_MAP.fetch(raw, raw.downcase.gsub(/[^\w]+/, "_").gsub(/\A_+|_+\z/, ""))
  end

  def normalize_value(key, value)
    stripped = value.to_s.strip
    return stripped unless %w[compressed_public_key private_key].include?(key)

    stripped.delete_prefix("0x")
  end
end

if $PROGRAM_NAME == __FILE__
  EthereumNewFixtureNormalizer.run
end
