# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
There are currently no unreleased changes.

## [v1.0.0] - 2022-08-29
### Changed
- Upgraded to Go 1.18.
- Upgraded dependencies (including security updates for [jwx library](https://github.com/lestrrat-go/jwx))  .
- `BOUNCER_SIGNING_METHOD` variable renamed to `BOUNCER_SIGNING_ALG` and now reflects the values listed [here](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2@v2.0.6/jwa#SignatureAlgorithm).

### Added
- `BOUNCER_REQUEST_TIMEOUT_IN_SEC` variable for setting request timeouts.

## [v0.1.0] - 2021-06-03
### Changed
- Backing JWT library switched to [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).
- Upgraded to Go 1.16.
- Elliptic curve signing method parameter renamed from `EC` to `ECDSA`.

### Removed
- `ignoreNotBefore` and `ignoreExpiration` settings. These claims are now always validated if they are included in the token.

## [v0.0.2] - 2021-03-25
### Fixed
- Query parameters in request causing route matching failures when request paths are received through headers.

## [v0.0.1] - 2020-06-12
### Added
- Support for original request path and method specification through headers (see [nginx docs](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)).
- Server and Authentication sections to Config.

### Removed
- JWT validation related flags moved to YAML configuration.

## v0.0.0 - 2020-06-01
This is the first version that includes the following functionality:
- YAML configuration support
    - Route matching with standard wildcards
    - Array and value claim checks
- HMAC, RSA and EC signing key support for JWT authentication
- Claims-based authorization
- Pure authorization server and reverse proxy modes

[Unreleased]: https://github.com/kaancfidan/bouncer/compare/v1.0.0...master
[v1.0.0]: https://github.com/kaancfidan/bouncer/compare/v0.1.0...v1.0.0
[v0.1.0]: https://github.com/kaancfidan/bouncer/compare/v0.0.2...v0.1.0
[v0.0.2]: https://github.com/kaancfidan/bouncer/compare/v0.0.1...v0.0.2
[v0.0.1]: https://github.com/kaancfidan/bouncer/compare/v0.0.0...v0.0.1
