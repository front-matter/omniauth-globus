# omniauth-globus

[![Identifier](https://img.shields.io/badge/doi-10.14454%2F81gp--9y63-fca709.svg)](https://doi.org/10.14454/81gp-9y63)
[![Gem Version](https://badge.fury.io/rb/omniauth-globus.svg)](https://badge.fury.io/rb/omniauth-globus)
[![Build Status](https://travis-ci.com/datacite/omniauth-globus.svg?branch=master)](https://travis-ci.com/datacite/omniauth-globus)
[![Test Coverage](https://api.codeclimate.com/v1/badges/13f9467872e9a688e9cb/test_coverage)](https://codeclimate.com/github/datacite/omniauth-globus/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/13f9467872e9a688e9cb/maintainability)](https://codeclimate.com/github/datacite/omniauth-globus/maintainability)

Globus OAuth 2.0 Strategy for the [OmniAuth Ruby authentication framework](http://www.omniauth.org), with support for OpenID Connect.

Provides basic support for authenticating a client application via the [Globus service](http://globus.org).

## Installation

The usual way with Bundler: add the following to your `Gemfile` to install the current version of the gem:

```ruby
gem 'omniauth-globus'
```

Then run `bundle install` to install into your environment.

You can also install the gem system-wide in the usual way:

```bash
gem install omniauth-globus
```

## Getting started

Like other OmniAuth strategies, `OmniAuth::Strategies::Globus` is a piece of Rack middleware. Please read the OmniAuth documentation for detailed instructions: https://github.com/intridea/omniauth.

Register a client application with Globus [here](https://developers.globus.org/).

You can then configure your client application using Omniauth or [Devise](https://github.com/plataformatec/devise) and the credentials obtained from Globus:

```ruby
use OmniAuth::Builder do
  provider :globus, ENV['GLOBUS_CLIENT_ID'], ENV['GLOBUS_CLIENT_SECRET']
end
```

```ruby
# in config/initializers/devise.rb
config.omniauth :globus, ENV["GLOBUS_CLIENT_ID"], 
                         ENV["GLOBUS_CLIENT_SECRET"]
```

## Development

We use rspec for unit testing:

```
bundle exec rspec
```

Follow along via [Github Issues](https://github.com/datacite/omniauth-globus/issues).

### Note on Patches/Pull Requests

* Fork the project
* Write tests for your new feature or a test that reproduces a bug
* Implement your feature or make a bug fix
* Do not mess with Rakefile, version or history
* Commit, push and make a pull request. Bonus points for topical branches.

## License
**omniauth-globus** is released under the [MIT License](https://github.com/datacite/omniauth-orcid/blob/master/LICENSE.md).
