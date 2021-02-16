/* eslint-disable @typescript-eslint/ban-types */
import { promisify } from 'util';
import { ErrorRequestHandler, Request, Response, RequestHandler } from 'express';
import basicAuth from 'basic-auth';
import * as jwt from 'jsonwebtoken';
import { asyncMiddleware } from '@valbo/async-middleware';
import { InternalServerErrorError, UnauthorizedError, ForbiddenError } from '@valbo/http-errors';

const jwtSign = promisify<object, string, jwt.SignOptions, string>(jwt.sign);
const jwtVerify = promisify<string, string, jwt.VerifyOptions, { sub: string }>(jwt.verify);

export type Resolver<T> = T | ((request: Request, response: Response) => T);

function isResolved<T>(resolver: Resolver<T>): resolver is T {
  return typeof resolver !== 'function';
}

export function resolve<T>(request: Request, response: Response, resolver: Resolver<T>): T {
  return isResolved(resolver) ? resolver : resolver(request, response);
}

// will be called to authenticate a user, e.g. a database function
export interface AuthenticationFunction {
  (username: string, password?: string): Promise<object | undefined>;
}

// will be called to authorize a user, e.g. if the user has the required role
export interface AuthorizationFunction<User extends object, Role extends string> {
  (user: User, ...roles: Role[]): boolean;
}

export interface BasicAuthenticationOptions {
  authenticationFunction: AuthenticationFunction;
}

export interface TokenAuthenticationOptions {
  authenticationFunction: AuthenticationFunction;
  jwtSigningSecret: string;
  headerName: string; // the name of the header to use for authentication, e.g. x-access-token
  expiresIn?: number; // if set the token in the header will expire in X seconds
}

export interface AuthorizationOptions<User extends object, Role extends string> {
  authorizationFunction: AuthorizationFunction<User, Role>;
}

export function askBasicAuth(): RequestHandler {
  return asyncMiddleware(async (request, response, next) => {
    if (!('authorization' in request.headers)) {
      response.setHeader('WWW-Authenticate', `Basic realm="${request.hostname}"`);
      throw new UnauthorizedError('missing credentials in Authorization header');
    }
    next();
  });
}

export function verifyBasicAuth(options: Resolver<BasicAuthenticationOptions>): RequestHandler {
  return asyncMiddleware(async (request, response, next) => {
    const { authenticationFunction } = resolve(request, response, options);
    const nameAndPass = basicAuth(request);
    if (nameAndPass === undefined) {
      throw new UnauthorizedError('invalid Authorization basic auth header');
    }
    const user = await authenticationFunction(nameAndPass.name, nameAndPass.pass);
    if (user === undefined) {
      throw new UnauthorizedError('invalid username or password');
    }
    response.locals.user = user;
    next();
  });
}

export function verifyTokenAuth(options: Resolver<TokenAuthenticationOptions>): RequestHandler {
  return asyncMiddleware(async (request, response, next) => {
    const { authenticationFunction, jwtSigningSecret, headerName } = resolve(request, response, options);
    const header = request.headers[headerName] as string | undefined;
    if (header === undefined) {
      throw new UnauthorizedError(`missing ${headerName} header`);
    }
    let sub;
    try {
      ({ sub } = await jwtVerify(header, jwtSigningSecret, {}));
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedError(`expired token in ${headerName} header`);
      }
      throw new UnauthorizedError(`invalid token in ${headerName} header`);
    }
    const user = await authenticationFunction(sub);
    if (user === undefined) {
      throw new UnauthorizedError(`invalid username in ${headerName} header token`);
    }
    response.locals.user = user;
    next();
  });
}

export function setTokenAuth(options: Resolver<TokenAuthenticationOptions>): RequestHandler {
  return asyncMiddleware(async (request, response, next) => {
    const { jwtSigningSecret, headerName, expiresIn } = resolve(request, response, options);
    const username: string | undefined = response.locals.user?.username;
    if (username === undefined) {
      throw new InternalServerErrorError('missing response.locals.user.username');
    }
    const signOptions: jwt.SignOptions = { subject: username };
    if (expiresIn !== undefined) {
      signOptions.expiresIn = expiresIn;
    }
    const token = await jwtSign({}, jwtSigningSecret, signOptions);
    response.setHeader(headerName, token);
    next();
  });
}

export function allowRoles<User extends object, Role extends string>(
  options: Resolver<AuthorizationOptions<User, Role>>,
): (...roles: Role[]) => RequestHandler {
  return (...roles: Role[]): RequestHandler => (request, response, next): void => {
    const { authorizationFunction } = resolve(request, response, options);
    if (response.locals.user === undefined) {
      throw new InternalServerErrorError('missing response.locals.user');
    } else if (authorizationFunction(response.locals.user, ...roles)) {
      next();
    } else {
      next(new ForbiddenError(`user does not have the required role`));
    }
  };
}

export function nextRouteIfUnauthorized(): ErrorRequestHandler {
  return (error, request, response, next): void => {
    if (error.status === 401) {
      next('route');
    } else {
      next(error);
    }
  };
}

export function nextRouteIfForbidden(): ErrorRequestHandler {
  return (error, request, response, next): void => {
    if (error.status === 403) {
      next('route');
    } else {
      next(error);
    }
  };
}

export function sendUser(): RequestHandler {
  return asyncMiddleware(async (request, response) => {
    const user = response.locals.user as object | undefined;
    if (user === undefined) {
      throw new InternalServerErrorError('missing response.locals.user');
    }
    response.json({ user });
  });
}
