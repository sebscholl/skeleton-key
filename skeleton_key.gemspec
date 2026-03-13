# frozen_string_literal: true

require_relative "lib/skeleton_key/version"

Gem::Specification.new do |spec|
  spec.name          = "skeleton_key"
  spec.version       = SkeletonKey::VERSION
  spec.authors       = ["Sebastian Scholl"]
  spec.email         = ["sebscholl@gmail.com"]

  spec.summary       = "Deterministic wallet recovery and derivation across chains"
  spec.description   = "SkeletonKey provides deterministic wallet recovery, seed normalization, and key derivation for Bitcoin, Ethereum, and Solana."
  spec.homepage      = "https://github.com/sebscholl/skeleton-key"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.2.0"

  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").select do |f|
      f.match(%r{^(bin/|lib/|LICENSE|README)})
    end
  end

  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["documentation_uri"] = "#{spec.homepage}#readme"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.add_development_dependency "rspec", "~> 3.12"
end
