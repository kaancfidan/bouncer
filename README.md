# jwt-bouncer ![bouncer](https://github.com/kaancfidan/jwt-bouncer/blob/master/gopher.png)
![Go](https://github.com/kaancfidan/jwt-bouncer/workflows/Go/badge.svg) [![Maintainability](https://api.codeclimate.com/v1/badges/e0018675c1b3b0beae61/maintainability)](https://codeclimate.com/github/kaancfidan/jwt-bouncer/maintainability) [![codecov](https://img.shields.io/codecov/c/github/kaancfidan/jwt-bouncer)](https://codecov.io/gh/kaancfidan/jwt-bouncer)

JWT Bouncer is a sidecar reverse proxy for authentication and authorization through [JSON Web Tokens (JWT)](http://jwt.io). 

## Purpose
[Sidecar deployment](https://docs.microsoft.com/en-us/azure/architecture/patterns/sidecar) for authentication and authorization excludes related logic out of application codebases. Although it can be used alongside monolithic apps, it is much more relevant to microservice architectures where changing & redeploying tens or hundreds of services just for an added authorization policy (e.g. a new role) is not feasible. 

There already exist excellent solutions, (one great example is [Envoy](https://www.envoyproxy.io/) + [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/envoy-authorization/)) but because authorization is complicated and these solutions try to cater to everyone, the configuration step is also inherently complicated and error-prone.

JWT Bouncer mostly borrows its design from [claims-based authorization in .NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1) and provides opinions on means of authorization to simplify the configuration process to a simple YAML.

## Current status
The project is in its infancy, does not have MVP features yet and is far from being production-grade.
