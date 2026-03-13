# frozen_string_literal: true

require "bundler/gem_tasks"

desc "Run syntax lint checks across the repository"
task :lint do
  ruby_files = FileList[
    "bin/*",
    "lib/**/*.rb",
    "spec/**/*.rb",
    "*.gemspec",
    "Rakefile"
  ]

  sh "ruby", "-wc", *ruby_files
end

desc "Run the full RSpec suite"
task :spec do
  sh "bundle", "exec", "rspec"
end

desc "Run lint and test validation"
task default: %i[lint spec]
