/* eslint-disable import/no-extraneous-dependencies */
import express, { ErrorRequestHandler, RequestHandler } from 'express';
import supertest from 'supertest';
import * as jwt from 'jsonwebtoken';
import { InternalServerErrorError, UnauthorizedError, ForbiddenError } from '@valbo/http-errors';
import {
  AuthenticationFunction,
  AuthorizationFunction,
  askBasicAuth,
  verifyBasicAuth,
  verifyTokenAuth,
  setTokenAuth,
  allowRoles,
  nextRouteIfUnauthorized,
  nextRouteIfForbidden,
  sendUser,
} from '../src';

const username = 'alice';
const password = '12345678';
const jwtSigningSecret = 'jwtSigningSecret';
const headerName = 'x-access-token';
const expiresIn = 24 * 60 * 60;

const authenticationFunctionUser: AuthenticationFunction = async () => ({ username, password });
const authenticationFunctionUndefined: AuthenticationFunction = async () => undefined;
const authenticationFunctionThrow: AuthenticationFunction = async () => {
  throw new InternalServerErrorError();
};

const setUser: (user: unknown) => RequestHandler = user => (request, response, next) => {
  response.locals.user = user;
  next();
};

const throwError: (error: unknown) => RequestHandler = error => () => {
  throw error;
};

type UserRole = 'admin' | 'dev' | 'user';

interface User {
  roles: UserRole[];
}

const authorizationFunction: AuthorizationFunction<User, UserRole> = (user, ...roles) => roles.some(role => user.roles.includes(role));

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const sendError: ErrorRequestHandler = (error, request, response, next) => {
  const httpError = {
    status: error.status || 500,
    name: error.name || InternalServerErrorError.name,
    message: error.message || '',
  };
  response.status(httpError.status).json({ error: httpError });
};

const sendEmpty: RequestHandler = (request, response) => {
  response.json({});
};

const authorizationBasicOk = 'Basic YWxpY2U6MTIzNDU2Nzg=';
const authorizationBasicError = '';
const tokenOk = jwt.sign({}, jwtSigningSecret, { subject: username });
const tokenError = jwt.sign({}, 'wrongSecret', { subject: username });
const tokenExpired = jwt.sign({ exp: Math.floor(Date.now() / 1000) - 60 }, jwtSigningSecret, { subject: username });

describe('askBasicAuth()', () => {
  test('should set the www-authenticate header and next an error when the authorization header is missing', async () => {
    const app = express().use(askBasicAuth()).use(sendEmpty).use(sendError);
    const response = await supertest(app).get('/');
    expect(response.header['www-authenticate']).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() when the authorization header exists', async () => {
    const app = express().use(askBasicAuth()).use(sendEmpty).use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicOk);
    expect(response.status).toBe(200);
  });
});

describe('verifyBasicAuth()', () => {
  test('should next() an invalid credentials error when the authorization header is missing', async () => {
    const app = express()
      .use(verifyBasicAuth({ authenticationFunction: authenticationFunctionUser }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() an invalid credentials error when basicAuth cannot decode the authorization header', async () => {
    const app = express()
      .use(verifyBasicAuth({ authenticationFunction: authenticationFunctionUser }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicError);
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() the error thrown by the authentication function', async () => {
    const app = express()
      .use(verifyBasicAuth({ authenticationFunction: authenticationFunctionThrow }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicOk);
    expect(response.status).toBe(500);
    expect(response.body.error.name).toBe(InternalServerErrorError.name);
  });

  test('should next() an invalid credentials error when the authentication function returns undefined', async () => {
    const app = express()
      .use(verifyBasicAuth({ authenticationFunction: authenticationFunctionUndefined }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicOk);
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() when the authentication function returns an object', async () => {
    const app = express()
      .use(verifyBasicAuth({ authenticationFunction: authenticationFunctionUser }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicOk);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
  });

  test('should work when called with an options resolver', async () => {
    const app = express()
      .use(verifyBasicAuth(() => ({ authenticationFunction: authenticationFunctionUser })))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set('Authorization', authorizationBasicOk);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
  });
});

describe('verifyTokenAuth()', () => {
  const authOptions = { jwtSigningSecret, headerName };

  test('should next() a missing credentials error when the access header is missing', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() an invalid credentials error when jwt.verify() throws a regular error', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenError);
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() an expired credentials error when jwt.verify() throws an TokenExpiredError', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenExpired);
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() the error thrown by the authentication function', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionThrow, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(500);
    expect(response.body.error.name).toBe(InternalServerErrorError.name);
  });

  test('should next() an invalid credentials error when the authentication function returns undefined', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUndefined, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(401);
    expect(response.body.error.name).toBe(UnauthorizedError.name);
  });

  test('should next() when the authentication function returns an object', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
  });

  test('should work when called with an options resolver', async () => {
    const app = express()
      .use(verifyTokenAuth(() => ({ authenticationFunction: authenticationFunctionUser, ...authOptions })))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(200);
    expect(response.body).toEqual({});
  });
});

describe('setTokenAuth()', () => {
  const authOptions = { jwtSigningSecret, headerName };

  test('should throw when response.locals.user.username is undefined', async () => {
    const app = express()
      .use(setTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(500);
    expect(response.body.error.name).toBe(InternalServerErrorError.name);
  });

  test('should put the jwt in the header and call next()', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(setTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(200);
    const token = response.header[headerName];
    expect(token).toBeDefined();
    const payload = jwt.verify(token, jwtSigningSecret) as { sub: string };
    expect(payload.sub).toBe(username);
  });

  test('should set the exp claim in the token when expiresIn is provided', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(setTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions, expiresIn }))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(200);
    const token = response.header[headerName];
    expect(token).toBeDefined();
    const payload = jwt.verify(token, jwtSigningSecret) as { exp: number; iat: number };
    expect(payload.exp - payload.iat).toBe(expiresIn);
  });

  test('should work when called with an options resolver', async () => {
    const app = express()
      .use(verifyTokenAuth({ authenticationFunction: authenticationFunctionUser, ...authOptions }))
      .use(setTokenAuth(() => ({ authenticationFunction: authenticationFunctionUser, ...authOptions })))
      .use(sendEmpty)
      .use(sendError);
    const response = await supertest(app).get('/').set(headerName, tokenOk);
    expect(response.status).toBe(200);
    const token = response.header[headerName];
    expect(token).toBeDefined();
    const payload = jwt.verify(token, jwtSigningSecret) as { sub: string };
    expect(payload.sub).toBe(username);
  });
});

describe('allowRoles()', () => {
  test('should throw an internal server error when response.locals.user is missing', async () => {
    const allow = allowRoles<User, UserRole>({ authorizationFunction });
    const app = express().use(allow('admin')).use(sendError).use(sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(500);
  });

  test('should throw a forbidden error when the authorization function returns false', async () => {
    const allow = allowRoles<User, UserRole>({ authorizationFunction });
    const app = express()
      .use(setUser({ roles: [] }))
      .use(allow('admin'))
      .use(sendError)
      .use(sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(403);
  });

  test('should next when the authorization function returns true', async () => {
    const allow = allowRoles<User, UserRole>({ authorizationFunction });
    const app = express()
      .use(setUser({ roles: ['admin'] }))
      .use(allow('admin'))
      .use(sendError)
      .use(sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(200);
  });
});

describe('nextRouteIfUnauthorized()', () => {
  test('should capture an unauthorized error and skip to the next route', async () => {
    const app = express().use(throwError(new UnauthorizedError()), nextRouteIfUnauthorized()).use(sendError).use(sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(200);
  });

  test('should send again any error other than unauthorized', async () => {
    const app = express().use(throwError(new InternalServerErrorError()), nextRouteIfUnauthorized(), sendError, sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(500);
  });
});

describe('nextRouteIfForbidden()', () => {
  test('should capture a forbidden error and skip to the next route', async () => {
    const app = express().use(throwError(new ForbiddenError()), nextRouteIfForbidden()).use(sendError).use(sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(200);
  });

  test('should send again any error other than forbidden', async () => {
    const app = express().use(throwError(new InternalServerErrorError()), nextRouteIfForbidden(), sendError, sendEmpty);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(500);
  });
});

describe('sendUser()', () => {
  test('should send the user in the response', async () => {
    const app = express()
      .use((request, response, next) => {
        response.locals.user = { username };
        next();
      })
      .use(sendUser());
    const response = await supertest(app).get('/');
    expect(response.status).toBe(200);
    expect(response.body.user.username).toBe(username);
  });

  test('should throw an internal server error error when response.locals.user is missing', async () => {
    const app = express().use(sendUser()).use(sendError);
    const response = await supertest(app).get('/');
    expect(response.status).toBe(500);
    expect(response.body.error.name).toBe(InternalServerErrorError.name);
  });
});
