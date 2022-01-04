"use strict";

/**
 * Module dependencies.
 */

const crypto = require("crypto");

const randomBytes = (size) => {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(size, (err, buf) => {
      if (err) {
        reject(err);
      } else {
        resolve(buf);
      }
    });
  });
};

/**
 * Export `TokenUtil`.
 */

module.exports = {
  /**
   * Generate random token.
   */

  generateRandomToken() {
    return randomBytes(256).then((buffer) => {
      return crypto.createHash("sha1").update(buffer).digest("hex");
    });
  },
};
