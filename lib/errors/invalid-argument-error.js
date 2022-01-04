"use strict";

/**
 * Module dependencies.
 */

const _ = require("lodash");
const OAuthError = require("./oauth-error");
const util = require("util");

/**
 * Constructor.
 */

function InvalidArgumentError(message, properties) {
  properties = _.assign(
    {
      code: 500,
      name: "invalid_argument",
    },
    properties
  );

  OAuthError.call(this, message, properties);
}

/**
 * Inherit prototype.
 */

util.inherits(InvalidArgumentError, OAuthError);

/**
 * Export constructor.
 */

module.exports = InvalidArgumentError;
