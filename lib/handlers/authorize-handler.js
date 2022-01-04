"use strict";

/**
 * Module dependencies.
 */

const _ = require("lodash");
const AccessDeniedError = require("../errors/access-denied-error");
const AuthenticateHandler = require("../handlers/authenticate-handler");
const InvalidArgumentError = require("../errors/invalid-argument-error");
const InvalidClientError = require("../errors/invalid-client-error");
const InvalidRequestError = require("../errors/invalid-request-error");
const InvalidScopeError = require("../errors/invalid-scope-error");
const UnsupportedResponseTypeError = require("../errors/unsupported-response-type-error");
const OAuthError = require("../errors/oauth-error");
const promisify = require("../utils/promisify-any");
const Request = require("../request");
const Response = require("../response");
const ServerError = require("../errors/server-error");
const UnauthorizedClientError = require("../errors/unauthorized-client-error");
const is = require("../validator/is");
const tokenUtil = require("../utils/token-util");
const url = require("url");

/**
 * Response types.
 */

const responseTypes = {
  code: require("../response-types/code-response-type"),
  //token: require('../response-types/token-response-type')
};

/**
 * Constructor.
 */

function AuthorizeHandler(options) {
  options = options || {};

  if (options.authenticateHandler && !options.authenticateHandler.handle) {
    throw new InvalidArgumentError("Invalid argument: authenticateHandler does not implement `handle()`");
  }

  if (!options.authorizationCodeLifetime) {
    throw new InvalidArgumentError("Missing parameter: `authorizationCodeLifetime`");
  }

  if (!options.model) {
    throw new InvalidArgumentError("Missing parameter: `model`");
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `getClient()`");
  }

  if (!options.model.saveAuthorizationCode) {
    throw new InvalidArgumentError("Invalid argument: model does not implement `saveAuthorizationCode()`");
  }

  this.allowEmptyState = options.allowEmptyState;
  this.authenticateHandler = options.authenticateHandler || new AuthenticateHandler(options);
  this.authorizationCodeLifetime = options.authorizationCodeLifetime;
  this.model = options.model;
}

/**
 * Authorize Handler.
 */

AuthorizeHandler.prototype.handle = async function handle(request, response) {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError("Invalid argument: `request` must be an instance of Request");
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError("Invalid argument: `response` must be an instance of Response");
  }

  if ("false" === request.query.allowed) {
    throw new AccessDeniedError("Access denied: user denied access to application");
  }

  const [expiresAt, client, user] = Promise.all([
    this.getAuthorizationCodeLifetime(),
    this.getClient(request),
    this.getUser(request, response),
  ]);

  try {
    const uri = this.getRedirectUri(request, client);

    const requestedScope = this.getScope(request);

    const validScope = await this.validateScope(user, client, requestedScope);

    const scope = validScope;

    const authorizationCode = await this.generateAuthorizationCode(client, user, scope);

    const state = this.getState(request);
    const ResponseType = this.getResponseType(request);

    const code = await this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);

    const responseType = new ResponseType(code.authorizationCode);
    const redirectUri = this.buildSuccessRedirectUri(uri, responseType);

    this.updateResponse(response, redirectUri, state);
  } catch (err) {
    let e = err;
    if (!(e instanceof OAuthError)) {
      e = new ServerError(e);
    }

    const redirectUri = this.buildErrorRedirectUri(uri, e);

    this.updateResponse(response, redirectUri, state);

    throw e;
  }
};

/**
 * Generate authorization code.
 */

AuthorizeHandler.prototype.generateAuthorizationCode = function generateAuthorizationCode(client, user, scope) {
  if (this.model.generateAuthorizationCode) {
    return promisify(this.model.generateAuthorizationCode, 3).call(this.model, client, user, scope);
  }

  return tokenUtil.generateRandomToken();
};

/**
 * Get authorization code lifetime.
 */

AuthorizeHandler.prototype.getAuthorizationCodeLifetime = function getAuthorizationCodeLifetime() {
  const expires = new Date();

  expires.setSeconds(expires.getSeconds() + this.authorizationCodeLifetime);
  return expires;
};

/**
 * Get the client from the model.
 */

AuthorizeHandler.prototype.getClient = function getClient(request) {
  const clientId = request.body.client_id || request.query.client_id;

  if (!clientId) {
    throw new InvalidRequestError("Missing parameter: `client_id`");
  }

  if (!is.vschar(clientId)) {
    throw new InvalidRequestError("Invalid parameter: `client_id`");
  }

  const redirectUri = request.body.redirect_uri || request.query.redirect_uri;

  if (redirectUri && !is.uri(redirectUri)) {
    throw new InvalidRequestError("Invalid request: `redirect_uri` is not a valid URI");
  }

  return promisify(this.model.getClient, 2)
    .call(this.model, clientId, null)
    .then((client) => {
      if (!client) {
        throw new InvalidClientError("Invalid client: client credentials are invalid");
      }

      if (!client.grants) {
        throw new InvalidClientError("Invalid client: missing client `grants`");
      }

      if (!_.includes(client.grants, "authorization_code")) {
        throw new UnauthorizedClientError("Unauthorized client: `grant_type` is invalid");
      }

      if (!client.redirectUris || 0 === client.redirectUris.length) {
        throw new InvalidClientError("Invalid client: missing client `redirectUri`");
      }

      if (redirectUri && !_.includes(client.redirectUris, redirectUri)) {
        throw new InvalidClientError("Invalid client: `redirect_uri` does not match client value");
      }

      return client;
    });
};

/**
 * Validate requested scope.
 */
AuthorizeHandler.prototype.validateScope = function validateScope(user, client, scope) {
  if (this.model.validateScope) {
    return promisify(this.model.validateScope, 3)
      .call(this.model, user, client, scope)
      .then((scope) => {
        if (!scope) {
          throw new InvalidScopeError("Invalid scope: Requested scope is invalid");
        }

        return scope;
      });
  }

  return Promise.resolve(scope);
};

/**
 * Get scope from the request.
 */

AuthorizeHandler.prototype.getScope = function getScope(request) {
  const scope = request.body.scope || request.query.scope;

  if (!is.nqschar(scope)) {
    throw new InvalidScopeError("Invalid parameter: `scope`");
  }

  return scope;
};

/**
 * Get state from the request.
 */

AuthorizeHandler.prototype.getState = function getState(request) {
  const state = request.body.state || request.query.state;

  if (!this.allowEmptyState && !state) {
    throw new InvalidRequestError("Missing parameter: `state`");
  }

  if (!is.vschar(state)) {
    throw new InvalidRequestError("Invalid parameter: `state`");
  }

  return state;
};

/**
 * Get user by calling the authenticate middleware.
 */

AuthorizeHandler.prototype.getUser = function getUser(request, response) {
  if (this.authenticateHandler instanceof AuthenticateHandler) {
    return this.authenticateHandler.handle(request, response).get("user");
  }

  return promisify(this.authenticateHandler.handle, 2)(request, response).then((user) => {
    if (!user) {
      throw new ServerError("Server error: `handle()` did not return a `user` object");
    }

    return user;
  });
};

/**
 * Get redirect URI.
 */

AuthorizeHandler.prototype.getRedirectUri = function getRedirectUri(request, client) {
  return request.body.redirect_uri || request.query.redirect_uri || client.redirectUris[0];
};

/**
 * Save authorization code.
 */

AuthorizeHandler.prototype.saveAuthorizationCode = function saveAuthorizationCode(
  authorizationCode,
  expiresAt,
  scope,
  client,
  redirectUri,
  user
) {
  const code = {
    authorizationCode,
    expiresAt,
    redirectUri,
    scope,
  };
  return promisify(this.model.saveAuthorizationCode, 3).call(this.model, code, client, user);
};

/**
 * Get response type.
 */

AuthorizeHandler.prototype.getResponseType = function getResponseType(request) {
  const responseType = request.body.response_type || request.query.response_type;

  if (!responseType) {
    throw new InvalidRequestError("Missing parameter: `response_type`");
  }

  if (!_.has(responseTypes, responseType)) {
    throw new UnsupportedResponseTypeError("Unsupported response type: `response_type` is not supported");
  }

  return responseTypes[responseType];
};

/**
 * Build a successful response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildSuccessRedirectUri = function buildSuccessRedirectUri(redirectUri, responseType) {
  return responseType.buildRedirectUri(redirectUri);
};

/**
 * Build an error response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildErrorRedirectUri = function buildErrorRedirectUri(redirectUri, error) {
  const uri = url.parse(redirectUri);

  uri.query = {
    error: error.name,
  };

  if (error.message) {
    uri.query.error_description = error.message;
  }

  return uri;
};

/**
 * Update response with the redirect uri and the state parameter, if available.
 */

AuthorizeHandler.prototype.updateResponse = function updateResponse(response, redirectUri, state) {
  redirectUri.query = redirectUri.query || {};

  if (state) {
    redirectUri.query.state = state;
  }

  response.redirect(url.format(redirectUri));
};

/**
 * Export constructor.
 */

module.exports = AuthorizeHandler;
