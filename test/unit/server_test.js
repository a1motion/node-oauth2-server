/* eslint-disable no-empty-function */
"use strict";

/**
 * Module dependencies.
 */

const AuthenticateHandler = require("../../lib/handlers/authenticate-handler");
const AuthorizeHandler = require("../../lib/handlers/authorize-handler");
const Server = require("../../lib/server");
const TokenHandler = require("../../lib/handlers/token-handler");
const sinon = require("sinon");

/**
 * Test `Server`.
 */

describe("Server", () => {
  describe("authenticate()", () => {
    it("should call `handle`", () => {
      const model = {
        getAccessToken() {},
      };
      const server = new Server({ model });

      sinon.stub(AuthenticateHandler.prototype, "handle").returns(Promise.resolve());

      server.authenticate("foo");

      AuthenticateHandler.prototype.handle.callCount.should.equal(1);
      AuthenticateHandler.prototype.handle.firstCall.args[0].should.equal("foo");
      AuthenticateHandler.prototype.handle.restore();
    });

    it("should map string passed as `options` to `options.scope`", () => {
      const model = {
        getAccessToken() {},
        verifyScope() {},
      };
      const server = new Server({ model });

      sinon.stub(AuthenticateHandler.prototype, "handle").returns(Promise.resolve());

      server.authenticate("foo", "bar", "test");

      AuthenticateHandler.prototype.handle.callCount.should.equal(1);
      AuthenticateHandler.prototype.handle.firstCall.args[0].should.equal("foo");
      AuthenticateHandler.prototype.handle.firstCall.args[1].should.equal("bar");
      AuthenticateHandler.prototype.handle.firstCall.thisValue.should.have.property("scope", "test");
      AuthenticateHandler.prototype.handle.restore();
    });
  });

  describe("authorize()", () => {
    it("should call `handle`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const server = new Server({ model });

      sinon.stub(AuthorizeHandler.prototype, "handle").returns(Promise.resolve());

      server.authorize("foo", "bar");

      AuthorizeHandler.prototype.handle.callCount.should.equal(1);
      AuthorizeHandler.prototype.handle.firstCall.args[0].should.equal("foo");
      AuthorizeHandler.prototype.handle.restore();
    });
  });

  describe("token()", () => {
    it("should call `handle`", () => {
      const model = {
        getClient() {},
        saveToken() {},
      };
      const server = new Server({ model });

      sinon.stub(TokenHandler.prototype, "handle").returns(Promise.resolve());

      server.token("foo", "bar");

      TokenHandler.prototype.handle.callCount.should.equal(1);
      TokenHandler.prototype.handle.firstCall.args[0].should.equal("foo");
      TokenHandler.prototype.handle.restore();
    });
  });
});
