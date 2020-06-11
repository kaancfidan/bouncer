# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
There are currently no unreleased changes.

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

[Unreleased]: https://github.com/kaancfidan/bouncer/compare/v0.0.1...master
[v0.0.1]: https://github.com/kaancfidan/bouncer/compare/v0.0.0...v0.0.1
