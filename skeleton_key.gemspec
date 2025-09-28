# frozen_string_literal: true

require_relative "lib/skeleton_key/version"

Gem::Specification.new do |spec|
  spec.name          = "skeleton_key"
  spec.version       = SkeletonKey::VERSION
  spec.authors       = ["Your Name"]
  spec.email         = ["you@example.com"]

  spec.summary       = "A gem that provides a master key abstraction"
  spec.description   = "SkeletonKey provides key management utilities..."
  spec.homepage      = "https://github.com/yourname/skeleton_key"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.0.0"

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
  spec.metadata["changelog_uri"] = "#{spec.homepage}/CHANGELOG.md"
end
