"use strict";

/**
 * Module dependencies.
 */

const InvalidArgumentError = require("../errors/invalid-argument-error");

/**
 * Constructor.
 */

const modelAttributes = [
  "accessToken",
  "accessTokenExpiresAt",
  "refreshToken",
  "refreshTokenExpiresAt",
  "scope",
  "client",
  "user",
];

function TokenModel(data, options) {
  data = data || {};

  if (!data.accessToken) {
    throw new InvalidArgumentError("Missing parameter: `accessToken`");
  }

  if (!data.client) {
    throw new InvalidArgumentError("Missing parameter: `client`");
  }

  if (!data.user) {
    throw new InvalidArgumentError("Missing parameter: `user`");
  }

  if (data.accessTokenExpiresAt && !(data.accessTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError("Invalid parameter: `accessTokenExpiresAt`");
  }

  if (data.refreshTokenExpiresAt && !(data.refreshTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError("Invalid parameter: `refreshTokenExpiresAt`");
  }

  this.accessToken = data.accessToken;
  this.accessTokenExpiresAt = data.accessTokenExpiresAt;
  this.client = data.client;
  this.refreshToken = data.refreshToken;
  this.refreshTokenExpiresAt = data.refreshTokenExpiresAt;
  this.scope = data.scope;
  this.user = data.user;

  if (options && options.allowExtendedTokenAttributes) {
    this.customAttributes = {};

    for (const key in data) {
      // eslint-disable-next-line no-prototype-builtins
      if (data.hasOwnProperty(key) && modelAttributes.indexOf(key) < 0) {
        this.customAttributes[key] = data[key];
      }
    }
  }

  if (this.accessTokenExpiresAt) {
    this.accessTokenLifetime = Math.floor((this.accessTokenExpiresAt - new Date()) / 1000);
  }
}

/**
 * Export constructor.
 */

module.exports = TokenModel;
