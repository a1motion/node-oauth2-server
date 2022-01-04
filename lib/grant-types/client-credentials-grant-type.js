"use strict";

/**
 * Module dependencies.
 */

const AbstractGrantType = require("./abstract-grant-type");
const InvalidArgumentError = require("../errors/invalid-argument-error");
const InvalidGrantError = require("../errors/invalid-grant-error");
const promisify = require("../utils/promisify-any");
const util = require("util");

/**
 * Constructor.
 */

function ClientCredentialsGrantType(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError("Missing parameter: `model`");
  }

  if (!options.model.getUserFromClient) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `getUserFromClient()`");
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `saveToken()`");
  }

  AbstractGrantType.call(this, options);
}

/**
 * Inherit prototype.
 */

util.inherits(ClientCredentialsGrantType, AbstractGrantType);

/**
 * Handle client credentials grant.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.4.2
 */

ClientCredentialsGrantType.prototype.handle = async function handle(request, client) {
  if (!request) {
    throw new InvalidArgumentError("Missing parameter: `request`");
  }

  if (!client) {
    throw new InvalidArgumentError("Missing parameter: `client`");
  }

  const scope = this.getScope(request);

  const user = await this.getUserFromClient(client);
  return this.saveToken(user, client, scope);
};

/**
 * Retrieve the user using client credentials.
 */

ClientCredentialsGrantType.prototype.getUserFromClient = function getUserFromClient(client) {
  return promisify(this.model.getUserFromClient, 1)
    .call(this.model, client)
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

ClientCredentialsGrantType.prototype.saveToken = async function saveToken(user, client, scope) {
  const fns = [
    this.validateScope(user, client, scope),
    this.generateAccessToken(client, user, scope),
    this.getAccessTokenExpiresAt(client, user, scope),
  ];

  const [_scope, accessToken, accessTokenExpiresAt] = await Promise.all(fns);

  const token = {
    accessToken,
    accessTokenExpiresAt,
    scope: _scope,
  };

  return promisify(this.model.saveToken, 3).call(this.model, token, client, user);
};

/**
 * Export constructor.
 */

module.exports = ClientCredentialsGrantType;
