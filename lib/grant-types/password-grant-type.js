"use strict";

/**
 * Module dependencies.
 */

const AbstractGrantType = require("./abstract-grant-type");
const InvalidArgumentError = require("../errors/invalid-argument-error");
const InvalidGrantError = require("../errors/invalid-grant-error");
const InvalidRequestError = require("../errors/invalid-request-error");
const promisify = require("../utils/promisify-any");
const is = require("../validator/is");
const util = require("util");

/**
 * Constructor.
 */

function PasswordGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError("Missing parameter: `model`");
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `getUser()`");
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `saveToken()`");
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(PasswordGrantType, AbstractGrantType);

/**
 * Retrieve the user from the model using a username/password combination.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
 */

PasswordGrantType.prototype.handle = async function handle(request, client) {
  if (!request) {
    throw new InvalidArgumentError("Missing parameter: `request`");
  }

  if (!client) {
    throw new InvalidArgumentError("Missing parameter: `client`");
  }

  const scope = this.getScope(request);

  const user = await this.getUser(request);
  return this.saveToken(user, client, scope);
};

/**
 * Get user using a username/password combination.
 */

PasswordGrantType.prototype.getUser = function getUser(request) {
  if (!request.body.username) {
    throw new InvalidRequestError("Missing parameter: `username`");
  }

  if (!request.body.password) {
    throw new InvalidRequestError("Missing parameter: `password`");
  }

  if (!is.uchar(request.body.username)) {
    throw new InvalidRequestError("Invalid parameter: `username`");
  }

  if (!is.uchar(request.body.password)) {
    throw new InvalidRequestError("Invalid parameter: `password`");
  }

  return promisify(this.model.getUser, 2)
    .call(this.model, request.body.username, request.body.password)
    .then((user) => {
      if (!user) {
        throw new InvalidGrantError("Invalid grant: user credentials are invalid");
      }

      return user;
    });
};

/**
 * Save token.
 */

PasswordGrantType.prototype.saveToken = async function saveToken(user, client, scope) {
  const fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.generateRefreshToken(client, user, scope),
    this.getAccessTokenExpiresAt(),
    this.getRefreshTokenExpiresAt(),
  ];

  const [_scope, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt] = await Promise.all(fns);

  const token = {
    accessToken,
    accessTokenExpiresAt,
    refreshToken,
    refreshTokenExpiresAt,
    scope: _scope,
  };

  return promisify(this.model.saveToken, 3).call(this.model, token, client, user);
};

/**
 * Export constructor.
 */

module.exports = PasswordGrantType;
