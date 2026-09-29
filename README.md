# jwt-eddsa

[![Gem Version](https://badge.fury.io/rb/jwt-eddsa.svg)](https://badge.fury.io/rb/jwt-eddsa)
[![Build status](https://github.com/jwt/ruby-jwt-eddsa/actions/workflows/test.yml/badge.svg)](https://github.com/jwt/ruby-jwt-eddsa/actions/workflows/test.yml)

A library extending the ruby-jwt gem with EdDSA algorithms. Based on [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037).

## Installation

Add the gem to your Gemfile:

```
gem "jwt-eddsa"
```

And in your application add the following require:

```
require "jwt/eddsa"
```

## Usage

```ruby
private_key = Ed25519::SigningKey.new("b" * 32)
token = JWT.encode({pay: "load"}, private_key, "EdDSA")
payload, header = JWT.decode(token, private_key.verify_key, true, algorithm: "EdDSA")
```

OKP JWKs must specify `crv: "Ed25519"`. Importing a JWK with a missing or
unsupported curve (including `X25519` and `Ed448`) raises `JWT::JWKError`.

## Development

```
bundle install
bundle exec rake
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jwt/ruby-jwt-eddsa. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/jwt/ruby-jwt-eddsa/blob/main/CODE_OF_CONDUCT.md).

In this repository, pull request titles must follow the [Conventional Commit](https://www.conventionalcommits.org/) specification to ensure clear and consistent communication of changes.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the jwt-eddsa project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/jwt/ruby-jwt-eddsa/blob/main/CODE_OF_CONDUCT.md).
