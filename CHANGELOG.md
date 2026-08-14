# Changelog

## [1.0.0](https://github.com/jwt/ruby-jwt-eddsa/compare/v0.9.0...v1.0.0) (2026-08-14)


### ⚠ BREAKING CHANGES

* Auto-generated `kid` values for OKP JWKs are now computed from the RFC 8037 required members (crv, kty, x) instead of the incorrect (kty, n, x). Previously generated kid values will no longer match; keys with an explicitly provided kid are unaffected.

### Bug Fixes

* Change OKP JWK thumbprint to use crv/kty/x, not RSA's kty/n/x ([#26](https://github.com/jwt/ruby-jwt-eddsa/issues/26)) ([7760623](https://github.com/jwt/ruby-jwt-eddsa/commit/77606230f99ec6f7ec5ebaab939451fea0652bff))
* OKP JWK kid values now follow RFC 8037 thumbprints ([#26](https://github.com/jwt/ruby-jwt-eddsa/issues/26)) ([6eaf654](https://github.com/jwt/ruby-jwt-eddsa/commit/6eaf654750666d9c3122b46629eeaf9115971694))

## [0.9.0](https://github.com/jwt/ruby-jwt-eddsa/compare/v0.8.1...v0.9.0) (2025-06-28)


### Features

* Support resolving JWA from crv parameter in JWK ([#24](https://github.com/jwt/ruby-jwt-eddsa/issues/24)) ([76ab43b](https://github.com/jwt/ruby-jwt-eddsa/commit/76ab43b14c27f477c78e6a8aaee7bcfb56d1d4a7))

## [0.8.1](https://github.com/jwt/ruby-jwt-eddsa/compare/v0.8.0...v0.8.1) (2025-06-27)


### Bug Fixes

* Change the urls for the repo ([#22](https://github.com/jwt/ruby-jwt-eddsa/issues/22)) ([238d2ed](https://github.com/jwt/ruby-jwt-eddsa/commit/238d2ed6719d8f5e83e74907ac7ea81b4184bf05))

## [0.8.0](https://github.com/anakinj/jwt-eddsa/compare/v0.7.1...v0.8.0) (2024-09-15)


### Features

* Officially supported by ruby-jwt ([#19](https://github.com/anakinj/jwt-eddsa/issues/19)) ([cca6ecf](https://github.com/anakinj/jwt-eddsa/commit/cca6ecf3fb0054bee0c102af824584e80eccc1b6))

## [0.7.1](https://github.com/anakinj/jwt-eddsa/compare/v0.7.0...v0.7.1) (2024-08-24)


### Bug Fixes

* Compatibility with ruby-jwt ([#17](https://github.com/anakinj/jwt-eddsa/issues/17)) ([4c674a2](https://github.com/anakinj/jwt-eddsa/commit/4c674a2d628781d6dcc873198f6334a506983cc0))

## [0.7.0](https://github.com/anakinj/jwt-eddsa/compare/v0.6.0...v0.7.0) (2024-08-04)


### Features

* Always set `alg` header to `EdDSA` ([#13](https://github.com/anakinj/jwt-eddsa/issues/13)) ([daaa740](https://github.com/anakinj/jwt-eddsa/commit/daaa740e653c9786c7ac9c5d086ad5ef9c432df7))
* Replace rbnacl with ed25519 ([#9](https://github.com/anakinj/jwt-eddsa/issues/9)) ([a0f8200](https://github.com/anakinj/jwt-eddsa/commit/a0f8200d1d81ce5807539a54e6fac29c4065ac97))
* Support the `ED25519` reference when pointing to the algorithm ([#12](https://github.com/anakinj/jwt-eddsa/issues/12)) ([982ecf3](https://github.com/anakinj/jwt-eddsa/commit/982ecf31b68bde8d06bb791de0717b51fb5084e8))

## [0.6.0](https://github.com/anakinj/jwt-eddsa/compare/v0.5.0...v0.6.0) (2024-08-02)


### Features

* Initial version using rbnacl for crypto operations ([#5](https://github.com/anakinj/jwt-eddsa/issues/5)) ([adc259b](https://github.com/anakinj/jwt-eddsa/commit/adc259b68da1a928400e3f7f18dce498939ddef1))

## [0.5.0](https://github.com/anakinj/jwt-eddsa/compare/v0.4.0...v0.5.0) (2024-08-02)
