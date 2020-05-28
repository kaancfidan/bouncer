# Bouncer ![bouncer](https://github.com/kaancfidan/bouncer/blob/master/gopher.png)
[![Go](https://github.com/kaancfidan/bouncer/workflows/Go/badge.svg)](https://github.com/kaancfidan/bouncer/actions?query=workflow%3AGo) [![Go Report Card](https://goreportcard.com/badge/github.com/kaancfidan/bouncer)](https://goreportcard.com/report/github.com/kaancfidan/bouncer) [![Maintainability](https://api.codeclimate.com/v1/badges/a4d16c48c6d1b41e1ea9/maintainability)](https://codeclimate.com/github/kaancfidan/bouncer/maintainability) [![codecov](https://img.shields.io/codecov/c/github/kaancfidan/bouncer)](https://codecov.io/gh/kaancfidan/bouncer)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer?ref=badge_shield)

Bouncer is a [JWT]-based authentication and authorization service. 

## Purpose
[Sidecar deployment](https://docs.microsoft.com/en-us/azure/architecture/patterns/sidecar) for authentication and authorization excludes related logic out of application codebases. Although it can be used alongside monolithic apps, it is much more relevant to microservice architectures where changing & redeploying tens or hundreds of services just for an added authorization policy (e.g. a new role) is not feasible. 

There already exist excellent solutions, (one great example is [Envoy](https://www.envoyproxy.io/) + [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/envoy-authorization/)) but because authorization is complicated and these solutions try to cater to everyone, the configuration step is also inherently complicated and error-prone.

Bouncer mostly borrows its design from [claims-based authorization in .NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1) and provides opinions on means of authorization to simplify the configuration process to a simple YAML.

## Current status
The project is in its infancy, does not have MVP features yet and is far from being production-grade.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer?ref=badge_large)


[JWT]: (http://jwt.io/introduction)