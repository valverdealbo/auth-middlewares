# @valbo/auth-middlewares

Express middlewares to authenticate via basic auth or jwt and to authorize based on user role.

![npm (scoped)](https://img.shields.io/npm/v/@valbo/auth-middlewares)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
![Build Status](https://img.shields.io/github/workflow/status/valverdealbo/auth-middlewares/CI)
[![Coverage Status](https://coveralls.io/repos/github/valverdealbo/auth-middlewares/badge.svg?branch=main)](https://coveralls.io/github/valverdealbo/auth-middlewares?branch=main)
[![Known Vulnerabilities](https://snyk.io/test/github/valverdealbo/auth-middlewares/badge.svg?targetFile=package.json)](https://snyk.io/test/github/valverdealbo/auth-middlewares?targetFile=package.json)

## Contents

- [Install](#install)
- [Usage](#usage)
  - [Basic authentication](#basic-authentication)
  - [JWT authentication](#jwt-authentication)
  - [Role authorization](#role-authorization)
  - [Skipping middleware routes](#skipping-middleware-routes)
  - [Sending the user](#sending-the-user)
  - [Dynamic options](#dynamic-options)

## Install

```bash
npm install @valbo/auth-middlewares
```

## Usage

This package exports express middlewares for authentication via basic auth or JSON Web Token, and authorization based on user roles. See the [example](src/example.ts) file for a full example on how to use all these middlewares.

### Basic authentication

There are two basic authentication middlewares: **askBasicAuth()** and **verifyBasicAuth()**.

**askBasicAuth()** checks for an **Authorization** header in the request and if it is missing it throws a **401** error and sets the **WWW-Authenticate** response header so that a browser asks for credentials. Always follow this middleware with **verifyBasicAuth()** so that when the user enters his credentials they will be verified.

**verifyBasicAuth()** validates an **Authorization** header with basic auth data. If the credentials are valid the authenticated user will be copied into **response.locals.user** and if the credentials are invalid it will throw a **401** error. The middleware will call **options.authenticationFunction** with the username and password it gets from the basic auth header.

### JWT authentication

There are two JWT authentication middlewares: **verifyTokenAuth()** and **setTokenAuth()**.

**verifyTokenAuth()** validates a JWT in a header. If the credentials are valid the authenticated user will be copied into **response.locals.user** and if the credentials are invalid it will throw a **401** error. The middleware will call **options.authenticationFunction** with a username (the **sub** claim of the JWT) and no password.

**setTokenAuth()** creates a JWT and sets it in a response header. The json web token **sub** claim is **response.locals.user.username**. It will throw a **500** error if there is any problem creating the token.

### Role authorization

**allowRoles()** checks if the authenticated user has one of the required roles. If it does not it will throw a **403** error. The middleware will call **options.authorizationFunction** with the user in **response.locals.user** and the requested roles.

### Skipping middleware routes

The **nextRouteIfUnauthorized()** and **nextRouteIfForbidden()** middlewares skip to the next middleware route if they receive a **401** and **403** errors respectively. They can be used to have both a private and a public version of the same route, or different versions of the same route for different roles.  

### Sending the user

**sendUser()** sends the user in **response.locals.user** as the response body or throws a **500** if there is no user in **response.locals**.

### Dynamic options

The above middlewares that accept options are actually defined as:

```typescript
type Resolver<T> = T | ((request: Request, response: Response) => T);

function verifyBasicAuth(options: Resolver<BasicAuthenticationOptions>): RequestHandler;
function verifyTokenAuth(options: Resolver<TokenAuthenticationOptions>): RequestHandler;
function setTokenAuth(options: Resolver<TokenAuthenticationOptions>): RequestHandler;
function allowRoles<User extends object, Role extends string>(options: Resolver<AuthorizationOptions<User, Role>>,): (...roles: Role[]) => RequestHandler;
```

Which means that these middlewares accept either an options object or a function that receives a request and a response and returns an options object. The functional form of the options can be used to dynamically decide which options to use, for example:

- Allowing only certain roles to log in depending on the origin of the request, like a website only for admin users.
- Using different JWT header names depending on the origin of the request, allowing users to log in simultaneously in multiple websites with different credentials.
- Returning a JWT with a different expiration depending on the role of the user.
