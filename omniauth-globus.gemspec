# frozen_string_literal: true

require "date"
require File.expand_path("../lib/omniauth/globus/version", __FILE__)

Gem::Specification.new do |s|
  s.authors       = ["Martin Fenner"]
  s.email         = ["mfenner@datacite.org"]
  s.name          = "omniauth-globus"
  s.homepage      = "https://github.com/datacite/omniauth-globus"
  s.summary       = "Globus OpenId connect Strategy for OmniAuth 1.0"
  s.date          = Date.today
  s.description   = "Enables third-party client apps to authenticate with the Globus service via OpenID Connect"
  s.require_paths = ["lib"]
  s.version       = OmniAuth::Globus::VERSION
  s.extra_rdoc_files = ["README.md"]
  s.license       = "MIT"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")

  s.required_ruby_version = ">= 2.3"

  # Declary dependencies here, rather than in the Gemfile
  s.add_dependency "jwt", "~> 2.0"
  s.add_dependency "omniauth", "~> 1.9"
  s.add_dependency "omniauth-oauth2", "~> 1.6"
  s.add_development_dependency "bundler", "~> 1.0"
  s.add_development_dependency "codeclimate-test-reporter", "~> 1.0", ">= 1.0.9"
  s.add_development_dependency "rack-test", "~> 0.6.3"
  s.add_development_dependency "rspec", "~> 3.4"
  s.add_development_dependency "rubocop", "~> 0.68"
  s.add_development_dependency "simplecov", "~> 0.13.0"
  s.add_development_dependency "webmock", "~> 3.0", ">= 3.0.1"
end
