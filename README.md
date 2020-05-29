# Bouncer [![bouncer](https://github.com/kaancfidan/bouncer/blob/master/gopher.png)](https://gopherize.me/gopher/c9a63ec34e1f313f408fc4aa378666cead40a271)
[![Go](https://github.com/kaancfidan/bouncer/workflows/Go/badge.svg)](https://github.com/kaancfidan/bouncer/actions?query=workflow%3AGo) [![Go Report Card](https://goreportcard.com/badge/github.com/kaancfidan/bouncer)](https://goreportcard.com/report/github.com/kaancfidan/bouncer) [![Maintainability](https://api.codeclimate.com/v1/badges/a4d16c48c6d1b41e1ea9/maintainability)](https://codeclimate.com/github/kaancfidan/bouncer/maintainability) [![codecov](https://img.shields.io/codecov/c/github/kaancfidan/bouncer)](https://codecov.io/gh/kaancfidan/bouncer)
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
- It aims to be out-of-the-box compatible with [nginx], [traefik] and [envoy] without any development effort.

#### How it works
- The **API gateway** receives an HTTP request from the client and it forwards the request (usually without including the body) to **Bouncer**.
- **Bouncer** matches the request method and path to a configured **route policy**.
- If the **route policy** explicitly allows anonymous requests for the given method-path pair, a response with status code **200(OK)** is returned.  
- **Bouncer** extracts the [Bearer] token and validates it for authentication. If authentication fails, a response with status code **401(Unauthorized)** is returned.
- **Bouncer** extracts claims from the validated token and checks if all **claim policies** corresponding to the matched **route policies** are fulfilled. If not, a response with status code **403(Forbidden)** is returned.
- After all these challenges are passed, a response with status code **200(OK)** is returned.
- If the authorization response is successful, the **API gateway** forwards the request to the appropriate backend service. 

### Sidecar reverse proxy
**Bouncer** can also be deployed as a reverse proxy to intercept requests to your application and perform authentication & authorization challenges before forwarding them.

This deployment strategy can be seen as a convenience feature as not all HTTP servers are deployed to cloud clusters with API gateways.

#### How it works
When given an **upstream URL**, **Bouncer** performs the same checks as in the API gateway scenario, but rather than returning a response with **200(OK)**, it calls the upstream server. 

## Configuration 
Bouncer mostly borrows its design from [claims-based authorization in .NET Core](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1). Comparatively: 
- It is more flexible in route configuration, because it uses standard wildcard patterns to match paths.
- It is less flexible in claim policy configuration, because claim requirements can only be expressed in equality comparisons (and "contains" checks in case of array claims).

#### Employee example
The following configuration example is loosely based on the example provided in the above .NET Core documentation:

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

## Current status
The project is in its infancy, does not have MVP features yet and is far from being production-grade.

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkaancfidan%2Fbouncer?ref=badge_large)


[JWT]: http://jwt.io/introduction
[sidecar]: https://docs.microsoft.com/en-us/azure/architecture/patterns/sidecar
[API gateway]: https://microservices.io/patterns/apigateway.html
[nginx]: https://containo.us/traefik/
[traefik]: https://containo.us/traefik/
[envoy]: https://www.envoyproxy.io/
[Open Policy Agent]: https://www.openpolicyagent.org/
[OPA]: https://www.openpolicyagent.org/
[Rego]: https://www.openpolicyagent.org/docs/latest/#rego
[YAML]: https://yaml.org/
[Bearer]: https://swagger.io/docs/specification/authentication/bearer-authentication/