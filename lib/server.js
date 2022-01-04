/**
 * Module dependencies.
 */

const AuthenticateHandler = require("./handlers/authenticate-handler");
const AuthorizeHandler = require("./handlers/authorize-handler");
const InvalidArgumentError = require("./errors/invalid-argument-error");
const TokenHandler = require("./handlers/token-handler");
const nodeify = require("./utils/nodeify");
/**
 * Constructor.
 */

function OAuth2Server(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError("Missing parameter: `model`");
  }

  this.options = options;
}

/**
 * Authenticate a token.
 */

OAuth2Server.prototype.authenticate = async function authenticate(request, response, options, callback) {
  if (typeof options === "string") {
    options = { scope: options };
  }

  options = {
    addAcceptedScopesHeader: true,
    addAuthorizedScopesHeader: true,
    allowBearerTokensInQueryString: false,
    ...this.options,
    ...options,
  };

  return nodeify(new AuthenticateHandler(options).handle(request, response), callback);
};

/**
 * Authorize a request.
 */

OAuth2Server.prototype.authorize = async function authorize(request, response, options, callback) {
  options = {
    allowEmptyState: false,
    authorizationCodeLifetime: 5 * 60, // 5 minutes.

    ...this.options,
    ...options,
  };

  return nodeify(new AuthorizeHandler(options).handle(request, response), callback);
};

/**
 * Create a token.
 */

OAuth2Server.prototype.token = async function token(request, response, options, callback) {
  options = {
    accessTokenLifetime: 60 * 60, // 1 hour.
    refreshTokenLifetime: 60 * 60 * 24 * 14, // 2 weeks.
    allowExtendedTokenAttributes: false,
    requireClientAuthentication: {}, // defaults to true for all grant types

    ...this.options,
    ...options,
  };

  return nodeify(new TokenHandler(options).handle(request, response), callback);
};

/**
 * Export constructor.
 */

module.exports = OAuth2Server;
