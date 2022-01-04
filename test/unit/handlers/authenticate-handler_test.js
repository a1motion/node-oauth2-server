/* eslint-disable no-empty-function */
"use strict";

/**
 * Module dependencies.
 */

const AuthenticateHandler = require("../../../lib/handlers/authenticate-handler");
const Request = require("../../../lib/request");
const sinon = require("sinon");
const should = require("should");
const ServerError = require("../../../lib/errors/server-error");

/**
 * Test `AuthenticateHandler`.
 */

describe("AuthenticateHandler", () => {
  describe("getTokenFromRequest()", () => {
    describe("with bearer token in the request authorization header", () => {
      it("should call `getTokenFromRequestHeader()`", () => {
        const handler = new AuthenticateHandler({ model: { getAccessToken() {} } });
        const request = new Request({
          body: {},
          headers: { Authorization: "Bearer foo" },
          method: {},
          query: {},
        });

        sinon.stub(handler, "getTokenFromRequestHeader");

        handler.getTokenFromRequest(request);

        handler.getTokenFromRequestHeader.callCount.should.equal(1);
        handler.getTokenFromRequestHeader.firstCall.args[0].should.equal(request);
        handler.getTokenFromRequestHeader.restore();
      });
    });

    describe("with bearer token in the request query", () => {
      it("should call `getTokenFromRequestQuery()`", () => {
        const handler = new AuthenticateHandler({ model: { getAccessToken() {} } });
        const request = new Request({
          body: {},
          headers: {},
          method: {},
          query: { access_token: "foo" },
        });

        sinon.stub(handler, "getTokenFromRequestQuery");

        handler.getTokenFromRequest(request);

        handler.getTokenFromRequestQuery.callCount.should.equal(1);
        handler.getTokenFromRequestQuery.firstCall.args[0].should.equal(request);
        handler.getTokenFromRequestQuery.restore();
      });
    });

    describe("with bearer token in the request body", () => {
      it("should call `getTokenFromRequestBody()`", () => {
        const handler = new AuthenticateHandler({ model: { getAccessToken() {} } });
        const request = new Request({
          body: { access_token: "foo" },
          headers: {},
          method: {},
          query: {},
        });

        sinon.stub(handler, "getTokenFromRequestBody");

        handler.getTokenFromRequest(request);

        handler.getTokenFromRequestBody.callCount.should.equal(1);
        handler.getTokenFromRequestBody.firstCall.args[0].should.equal(request);
        handler.getTokenFromRequestBody.restore();
      });
    });
  });

  describe("getAccessToken()", () => {
    it("should call `model.getAccessToken()`", () => {
      const model = {
        getAccessToken: sinon.stub().returns({ user: {} }),
      };
      const handler = new AuthenticateHandler({ model });

      return handler
        .getAccessToken("foo")
        .then(() => {
          model.getAccessToken.callCount.should.equal(1);
          model.getAccessToken.firstCall.args.should.have.length(1);
          model.getAccessToken.firstCall.args[0].should.equal("foo");
          model.getAccessToken.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });

  describe("validateAccessToken()", () => {
    it("should fail if token has no valid `accessTokenExpiresAt` date", () => {
      const model = {
        getAccessToken() {},
      };
      const handler = new AuthenticateHandler({ model });

      let failed = false;
      try {
        handler.validateAccessToken({
          user: {},
        });
      } catch (err) {
        err.should.be.an.instanceOf(ServerError);
        failed = true;
      }

      failed.should.equal(true);
    });

    it("should succeed if token has valid `accessTokenExpiresAt` date", () => {
      const model = {
        getAccessToken() {},
      };
      const handler = new AuthenticateHandler({ model });
      try {
        handler.validateAccessToken({
          user: {},
          accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
        });
      } catch (_) {
        should.fail();
      }
    });
  });

  describe("verifyScope()", () => {
    it("should call `model.getAccessToken()` if scope is defined", () => {
      const model = {
        getAccessToken() {},
        verifyScope: sinon.stub().returns(true),
      };
      const handler = new AuthenticateHandler({
        addAcceptedScopesHeader: true,
        addAuthorizedScopesHeader: true,
        model,
        scope: "bar",
      });

      return handler
        .verifyScope("foo")
        .then(() => {
          model.verifyScope.callCount.should.equal(1);
          model.verifyScope.firstCall.args.should.have.length(2);
          model.verifyScope.firstCall.args[0].should.equal("foo", "bar");
          model.verifyScope.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });
});
