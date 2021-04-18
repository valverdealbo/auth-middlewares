// eslint-disable-next-line import/no-extraneous-dependencies
import express, { Request, Response } from 'express';
import {
  askBasicAuth,
  verifyBasicAuth,
  verifyTokenAuth,
  setTokenAuth,
  allowRoles,
  nextRouteIfUnauthorized,
  nextRouteIfForbidden,
  sendUser,
  AuthenticationFunction,
  BasicAuthenticationOptions,
  TokenAuthenticationOptions,
  AuthorizationFunction,
  AuthorizationOptions,
} from '.';

type User = {
  username: string;
  password: string;
  role: 'admin' | 'user';
};

const users: User[] = [
  { username: 'admin', password: '1234', role: 'admin' },
  { username: 'user', password: '5678', role: 'user' },
];

const authenticateUser: AuthenticationFunction = async (username: string, password?: string) =>
  users.find(user => user.username === username && (password === undefined || user.password === password));

const authorizeUser: AuthorizationFunction<User, User['role']> = (user, ...roles) => roles.some(role => user.role === role);

const options: BasicAuthenticationOptions & TokenAuthenticationOptions & AuthorizationOptions<User, User['role']> = {
  authenticationFunction: authenticateUser,
  authorizationFunction: authorizeUser,
  jwtSigningSecret: '1d2c468e-3b6b-4309-9b4c-04a890da7e76',
  headerName: 'x-access-token',
  expiresIn: 24 * 60 * 60,
};

const auth = {
  askBasicAuth: askBasicAuth(),
  verifyBasicAuth: verifyBasicAuth(options),
  verifyTokenAuth: verifyTokenAuth(options),
  setTokenAuth: setTokenAuth(options),
  allowRoles: allowRoles<User, User['role']>(options),
  nextRouteIfUnauthorized: nextRouteIfUnauthorized(),
  nextRouteIfForbidden: nextRouteIfForbidden(),
  sendUser: sendUser(),
};

const app = express();

// login with basic auth, send back user and JWT in header for future requests
app.get('/login', auth.askBasicAuth, auth.verifyBasicAuth, auth.setTokenAuth, auth.sendUser);

// private route for admins
app.get(
  '/data',
  auth.verifyTokenAuth,
  auth.nextRouteIfUnauthorized,
  auth.allowRoles('admin'),
  auth.nextRouteIfForbidden,
  (request: Request, response: Response) => {
    response.json({ data: 'admin private data' });
  },
);

// private route for users
app.get(
  '/data',
  auth.verifyTokenAuth,
  auth.nextRouteIfUnauthorized,
  auth.allowRoles('user'),
  auth.nextRouteIfForbidden,
  (request: Request, response: Response) => {
    response.json({ data: 'user private data' });
  },
);

// public route
app.get('/data', (request: Request, response: Response) => {
  response.json({ data: 'public data' });
});
