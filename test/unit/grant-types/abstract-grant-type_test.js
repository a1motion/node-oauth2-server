"use strict";

/**
 * Module dependencies.
 */

const AbstractGrantType = require("../../../lib/grant-types/abstract-grant-type");
const sinon = require("sinon");
const should = require("should");

/**
 * Test `AbstractGrantType`.
 */

describe("AbstractGrantType", () => {
  describe("generateAccessToken()", () => {
    it("should call `model.generateAccessToken()`", () => {
      const model = {
        generateAccessToken: sinon.stub().returns({ client: {}, expiresAt: new Date(), user: {} }),
      };
      const handler = new AbstractGrantType({ accessTokenLifetime: 120, model });

      return handler
        .generateAccessToken()
        .then(() => {
          model.generateAccessToken.callCount.should.equal(1);
          model.generateAccessToken.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });

  describe("generateRefreshToken()", () => {
    it("should call `model.generateRefreshToken()`", () => {
      const model = {
        generateRefreshToken: sinon.stub().returns({ client: {}, expiresAt: new Date(new Date() / 2), user: {} }),
      };
      const handler = new AbstractGrantType({ accessTokenLifetime: 120, model });

      return handler
        .generateRefreshToken()
        .then(() => {
          model.generateRefreshToken.callCount.should.equal(1);
          model.generateRefreshToken.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });
});
