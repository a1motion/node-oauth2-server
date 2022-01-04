"use strict";

/**
 * Module dependencies.
 */

const TokenUtil = require("../../../lib/utils/token-util");
const should = require("should");

/**
 * Test `TokenUtil` integration.
 */

describe("TokenUtil integration", () => {
  describe("generateRandomToken()", () => {
    it("should return a sha-1 token", () => {
      return TokenUtil.generateRandomToken()
        .then((token) => {
          token.should.be.a.sha1;
        })
        .catch(should.fail);
    });
  });
});
