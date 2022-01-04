"use strict";

/**
 * Module dependencies.
 */
const _ = require("lodash");
const util = require("util");
const statuses = require("statuses");
/**
 * Constructor.
 */

function OAuthError(messageOrError, properties) {
  let message = messageOrError instanceof Error ? messageOrError.message : messageOrError;
  const error = messageOrError instanceof Error ? messageOrError : null;
  if (_.isEmpty(properties)) {
    properties = {};
  }

  _.defaults(properties, { code: 500 });

  if (error) {
    properties.inner = error;
  }

  if (_.isEmpty(message)) {
    message = statuses[properties.code];
  }

  this.code = this.status = this.statusCode = properties.code;
  this.message = message;
  for (const key in properties) {
    if (key !== "code") {
      this[key] = properties[key];
    }
  }

  Error.captureStackTrace(this, OAuthError);
}

util.inherits(OAuthError, Error);

/**
 * Export constructor.
 */

module.exports = OAuthError;
