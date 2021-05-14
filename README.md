# Bouncer [![bouncer](https://raw.githubusercontent.com/kaancfidan/bouncer/master/gopher.png)](https://gopherize.me/gopher/c9a63ec34e1f313f408fc4aa378666cead40a271)
[![Go](https://github.com/kaancfidan/bouncer/workflows/Go/badge.svg)](https://github.com/kaancfidan/bouncer/actions?query=workflow%3AGo) [![Docker Pulls](https://img.shields.io/docker/pulls/kaancfidan/bouncer)](https://hub.docker.com/r/kaancfidan/bouncer) [![Docker Image Size (latest semver)](https://img.shields.io/docker/image-size/kaancfidan/bouncer?sort=semver)](https://hub.docker.com/r/kaancfidan/bouncer) [![Go Report Card](https://goreportcard.com/badge/github.com/kaancfidan/bouncer)](https://goreportcard.com/report/github.com/kaancfidan/bouncer) [![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability/kaancfidan/bouncer)](https://codeclimate.com/github/kaancfidan/bouncer/maintainability) [![codecov](https://img.shields.io/codecov/c/github/kaancfidan/bouncer)](https://codecov.io/gh/kaancfidan/bouncer)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer?ref=badge_shield)

Bouncer is a [JWT]-based authentication and authorization service. 

## Purpose
**Bouncer** aims to move authentication- and authorization-related logic out of application codebases. 

Although it can be used alongside monolithic apps, it is much more relevant to distributed architectures where changing and redeploying tens or hundreds of services just for an added authorization policy (e.g. a new role) is not feasible. 

**Bouncer** has 2 main modes of operation:
- Deployed as an authorization extension for an [API gateway]
- Deployed as a [sidecar] reverse proxy alongside each application instance separately

### Authorization extension
Widely-used reverse proxy solutions, like [nginx], [traefik] and [envoy], all integrate with external authorization services to check authorization status of each request. 

[Open Policy Agent] is an excellent tool that provides authorization using [Rego] scripts and if you are in the market for a flexible solution, and think that investing time is worthwhile in your case, you should stop reading this text and check it out.

As always though, flexibility of **OPA** comes at a cost:
- You need to invest time to understand Rego as a new (although relatively easy) scripting language.
- Each deployment is a new implementation of probably very similar policies & logic (e.g. jwt expiration check). 
- Although it can be integrated with **envoy**[*](https://www.openpolicyagent.org/docs/latest/envoy-authorization/) via configuration, **nginx**[*](https://github.com/summerwind/opa-nginx-rbac) and **traefik**[*](https://github.com/containous/traefik/issues/4894) currently require development to integrate.

As an example, [this blog post](https://engineering.etermax.com/api-authorization-with-kubernetes-traefik-and-open-policy-agent-23647fc384a1) demonstrates an authorization service implemented using **OPA** as a dependency and integrating it to **traefik**. 

**Bouncer** is the easier-to-use alternative to **OPA** in this scenario for the following reasons:
- It is configured with a simple [YAML].
- It is more opinionated, so expect less flexibility.
- It aims to be out-of-the-box compatible with **nginx**, **traefik** and **envoy** without any development effort.

#### How it works
- The **API gateway** receives an HTTP request from the client and forwards it (usually without including the body) to **Bouncer**.
- **Bouncer** matches the request method and path (i.e. GET /stuff/) to configured **route policies**.
- If the most specific<sup>1</sup> **route policy** that matches the request explicitly allows anonymous requests, a response with status code **200(OK)** is returned.  
- **Bouncer** extracts the [Bearer] token and validates it for authentication. If authentication fails, a response with status code **401(Unauthorized)** is returned.
- **Bouncer** extracts claims from the validated token and checks if all **claim policies** corresponding to the matched **route policies** are fulfilled. If not, a response with status code **403(Forbidden)** is returned.
- After all these challenges are passed, a response with status code **200(OK)** is returned.
- If the authorization response is successful, the **API gateway** forwards the request to the appropriate backend service. 

<sup>1</sup> The most specific route is the one that has the deepest path, the least number of wildcards and as a tie-breaker the one that specifies the request's method.

### Sidecar reverse proxy
**Bouncer** can also be deployed as a reverse proxy to intercept requests to your application and perform authentication & authorization challenges before forwarding them.

This deployment strategy can be seen as a convenience feature as not all HTTP servers are deployed to cloud clusters with API gateways.

#### How it works
When given an **upstream URL**, **Bouncer** performs the same checks as in the API gateway scenario, but rather than returning a response with **200(OK)**, it calls the upstream server. 

## Configuration 
**Bouncer** mostly borrows its design from [claims-based authorization in .NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1). Comparing it to the original design: 
- **Bouncer** is more flexible in route configuration, because it uses standard wildcard patterns to match paths.
- **Bouncer** is less flexible in claim policy configuration, because claim requirements can only be expressed in equality comparisons (and "contains" checks in case of array claims).

### Examples
#### Allow anonymous example
The following configuration depicts a system in which all requests are allowed in without any authentication, except DELETEs and the ones with intentions to destroy the server.

```yaml
claimPolicies: {} 

routePolicies: 
 - path: /** 
   allowAnonymous: true 
 - path: /** 
   methods: [DELETE] 
   allowAnonymous: false 
 - path: /destroy/server 
   allowAnonymous: false
```

#### User management example
The following is a mock user management system in which:
- The users are allowed to register themselves (anonymous requests allowed)
- Every other route requires authentication
- Deleting users also requires a special `permission` claim that:
  - either has a value equal to `DeleteUser` as in `"permission": "DeleteUser"`
  - or is an array that contains the `DeleteUser` value as in `"permission": ["AddUser", "ModifyUser", "DeleteUser"]`

```yaml
claimPolicies: 
 CanDeleteUsers: 
  - claim: permission
    values: [DeleteUser] 

routePolicies: 
 - path: /users/* 
   methods: [DELETE] 
   policyName: CanDeleteUsers 
 - path: /users/register 
   methods: [POST] 
   allowAnonymous: true
```

#### Employee example
The following configuration example is loosely based on the example provided in the [.NET Core docs](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1):

```yaml
claimPolicies:
 EmployeeOnly:
  - claim: employee_number
 Founders:
  - claim: employee_number
    values: [1,2,3,4,5]
 HumanResources:
  - claim: department
    values: [HumanResources]

routePolicies:
 - path: /vacation/**
   policyName: EmployeeOnly
 - path: /vacation/policy
   allowAnonymous: true
 - path: /vacation/*/
   methods: [PUT, PATCH]
   policyName: Founders
 - path: /salary/**
   policyName: EmployeeOnly
 - path: /salary/*/
   methods: [PUT, PATCH]
   policyName: HumanResources
```

## Current status
First version has been released! 🎉 It's not battle-tested yet, but it's a start. 

#### Current functionality in a nutshell:
- Static signing key configuration w/ HMAC, RSA and EC support
- Single valid issuer and audience configuration
- Token expiration, "not before" and "issued at" checks with clock skew tolerance
- Authorization policy config with YAML
- Reverse proxy mode without TLS termination 

## Usage
### Docker image
Create a volume directory:
```zsh
➜  ~ mkdir bouncer
```
Put a config YAML:
```zsh
➜  ~ echo "claimPolicies: {}\nroutePolicies: []\n" > bouncer/config.yaml
```
Run bouncer:
```zsh
➜  ~ docker run \
--name bouncer \
-d \
--restart always \
-e BOUNCER_SIGNING_METHOD=HMAC \
-e BOUNCER_SIGNING_KEY=ThisIsSupposedToBeALongStringOfBytesLikeSixtyFourCharactersLong. \
-v `pwd`/bouncer:/etc/bouncer \
kaancfidan/bouncer:latest
```

### Environment variables and command line flags
Every startup setting has an environment variable and a CLI flag counterpart. 

| Environment Variable | CLI Flag | Description |
| -------------------- | -------- | ----------- |
| BOUNCER_SIGNING_KEY | -k | Signing key to be used to validate tokens. Consider setting this variable through a file for multiline keys. e.g. `BOUNCER_SIGNING_KEY=$(cat rsa.pub)` |
| BOUNCER_SIGNING_METHOD | -m | Signing method. Accepted values are **[HMAC, RSA, ECDSA]**. |
| BOUNCER_CONFIG_PATH | -p | Config YAML path. **default = /etc/bouncer/config.yaml** |
| BOUNCER_LISTEN_ADDRESS | -l | TCP listen address. **default = :3512** |
| BOUNCER_UPSTREAM_URL | --url | Upstream URL to be used in reverse proxy mode. If not set, Bouncer runs in pure auth server mode. |

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer?ref=badge_large)


[JWT]: http://jwt.io/introduction
[sidecar]: https://docs.microsoft.com/en-us/azure/architecture/patterns/sidecar
[API gateway]: https://microservices.io/patterns/apigateway.html
[nginx]: https://www.nginx.com/
[traefik]: https://containo.us/traefik/
[envoy]: https://www.envoyproxy.io/
[Open Policy Agent]: https://www.openpolicyagent.org/
[OPA]: https://www.openpolicyagent.org/
[Rego]: https://www.openpolicyagent.org/docs/latest/#rego
[YAML]: https://yaml.org/
[Bearer]: https://swagger.io/docs/specification/authentication/bearer-authentication/
