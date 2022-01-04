/* eslint-disable no-empty-function */
/* eslint-disable no-new */
"use strict";

/**
 * Module dependencies.
 */

const AuthorizationCodeGrantType = require("../../../lib/grant-types/authorization-code-grant-type");
const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const InvalidGrantError = require("../../../lib/errors/invalid-grant-error");
const InvalidRequestError = require("../../../lib/errors/invalid-request-error");
const Request = require("../../../lib/request");
const ServerError = require("../../../lib/errors/server-error");
const should = require("should");

/**
 * Test `AuthorizationCodeGrantType` integration.
 */

describe("AuthorizationCodeGrantType integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `model` is missing", () => {
      try {
        new AuthorizationCodeGrantType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `model`");
      }
    });

    it("should throw an error if the model does not implement `getAuthorizationCode()`", () => {
      try {
        new AuthorizationCodeGrantType({ model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `getAuthorizationCode()`");
      }
    });

    it("should throw an error if the model does not implement `revokeAuthorizationCode()`", () => {
      try {
        const model = {
          getAuthorizationCode() {},
        };

        new AuthorizationCodeGrantType({ model });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `revokeAuthorizationCode()`");
      }
    });

    it("should throw an error if the model does not implement `saveToken()`", () => {
      try {
        const model = {
          getAuthorizationCode() {},
          revokeAuthorizationCode() {},
        };

        new AuthorizationCodeGrantType({ model });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `saveToken()`");
      }
    });
  });

  describe("handle()", () => {
    it("should throw an error if `request` is missing", () => {
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .handle()
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Missing parameter: `request`");
        });
    });

    it("should throw an error if `client` is invalid", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, expiresAt: new Date(new Date() * 2), user: {} };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .handle(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal("Server error: `getAuthorizationCode()` did not return a `client` object");
        });
    });

    it("should throw an error if `client` is missing", () => {
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, expiresAt: new Date(new Date() * 2), user: {} };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      try {
        grantType.handle(request, null);
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `client`");
      }
    });

    it("should return a token", () => {
      const client = { id: "foobar" };
      const token = {};
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, client: { id: "foobar" }, expiresAt: new Date(new Date() * 2), user: {} };
        },
        revokeAuthorizationCode() {
          return true;
        },
        saveToken() {
          return token;
        },
        validateScope() {
          return "foo";
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .handle(request, client)
        .then((data) => {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return Promise.resolve({
            authorizationCode: 12345,
            client: { id: "foobar" },
            expiresAt: new Date(new Date() * 2),
            user: {},
          });
        },
        revokeAuthorizationCode() {
          return true;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, client: { id: "foobar" }, expiresAt: new Date(new Date() * 2), user: {} };
        },
        revokeAuthorizationCode() {
          return true;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode(code, callback) {
          callback(null, {
            authorizationCode: 12345,
            client: { id: "foobar" },
            expiresAt: new Date(new Date() * 2),
            user: {},
          });
        },
        revokeAuthorizationCode(code, callback) {
          callback(null, {
            authorizationCode: 12345,
            client: { id: "foobar" },
            expiresAt: new Date(new Date() / 2),
            user: {},
          });
        },
        saveToken(tokenToSave, client, user, callback) {
          callback(null, tokenToSave);
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });
  });

  describe("getAuthorizationCode()", () => {
    it("should throw an error if the request body does not contain `code`", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        grantType.getAuthorizationCode(request, client);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `code`");
      }
    });

    it("should throw an error if `code` is invalid", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: "øå€£‰" }, headers: {}, method: {}, query: {} });

      try {
        grantType.getAuthorizationCode(request, client);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid parameter: `code`");
      }
    });

    it("should throw an error if `authorizationCode` is missing", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: authorization code is invalid");
        });
    });

    it("should throw an error if `authorizationCode.client` is missing", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345 };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal("Server error: `getAuthorizationCode()` did not return a `client` object");
        });
    });

    it("should throw an error if `authorizationCode.expiresAt` is missing", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, client: {}, user: {} };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal("Server error: `expiresAt` must be a Date instance");
        });
    });

    it("should throw an error if `authorizationCode.user` is missing", () => {
      const client = {};
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, client: {}, expiresAt: new Date() };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal("Server error: `getAuthorizationCode()` did not return a `user` object");
        });
    });

    it("should throw an error if the client id does not match", () => {
      const client = { id: 123 };
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, expiresAt: new Date(), client: { id: 456 }, user: {} };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: authorization code is invalid");
        });
    });

    it("should throw an error if the auth code is expired", () => {
      const client = { id: 123 };
      const date = new Date(new Date() / 2);
      const model = {
        getAuthorizationCode() {
          return { authorizationCode: 12345, client: { id: 123 }, expiresAt: date, user: {} };
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: authorization code has expired");
        });
    });

    it("should throw an error if the `redirectUri` is invalid", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: { id: "foobar" },
        expiresAt: new Date(new Date() * 2),
        redirectUri: "foobar",
        user: {},
      };
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return authorizationCode;
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: `redirect_uri` is not a valid URI");
        });
    });

    it("should return an auth code", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: { id: "foobar" },
        expiresAt: new Date(new Date() * 2),
        user: {},
      };
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return authorizationCode;
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      return grantType
        .getAuthorizationCode(request, client)
        .then((data) => {
          data.should.equal(authorizationCode);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: { id: "foobar" },
        expiresAt: new Date(new Date() * 2),
        user: {},
      };
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return Promise.resolve(authorizationCode);
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.getAuthorizationCode(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: { id: "foobar" },
        expiresAt: new Date(new Date() * 2),
        user: {},
      };
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode() {
          return authorizationCode;
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.getAuthorizationCode(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: { id: "foobar" },
        expiresAt: new Date(new Date() * 2),
        user: {},
      };
      const client = { id: "foobar" };
      const model = {
        getAuthorizationCode(code, callback) {
          callback(null, authorizationCode);
        },
        revokeAuthorizationCode() {},
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      grantType.getAuthorizationCode(request, client).should.be.an.instanceOf(Promise);
    });
  });

  describe("validateRedirectUri()", () => {
    it("should throw an error if `redirectUri` is missing", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: {},
        expiresAt: new Date(new Date() / 2),
        redirectUri: "http://foo.bar",
        user: {},
      };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return authorizationCode;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { code: 12345 }, headers: {}, method: {}, query: {} });

      try {
        grantType.validateRedirectUri(request, authorizationCode);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid request: `redirect_uri` is not a valid URI");
      }
    });

    it("should throw an error if `redirectUri` is invalid", () => {
      const authorizationCode = {
        authorizationCode: 12345,
        client: {},
        expiresAt: new Date(new Date() / 2),
        redirectUri: "http://foo.bar",
        user: {},
      };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return true;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({
        body: { code: 12345, redirect_uri: "http://bar.foo" },
        headers: {},
        method: {},
        query: {},
      });

      try {
        grantType.validateRedirectUri(request, authorizationCode);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid request: `redirect_uri` is invalid");
      }
    });
  });

  describe("revokeAuthorizationCode()", () => {
    it("should revoke the auth code", () => {
      const authorizationCode = { authorizationCode: 12345, client: {}, expiresAt: new Date(new Date() / 2), user: {} };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return true;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .revokeAuthorizationCode(authorizationCode)
        .then((data) => {
          data.should.equal(authorizationCode);
        })
        .catch(should.fail);
    });

    it("should throw an error when the auth code is invalid", () => {
      const authorizationCode = { authorizationCode: 12345, client: {}, expiresAt: new Date(new Date() / 2), user: {} };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return false;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .revokeAuthorizationCode(authorizationCode)
        .then((data) => {
          data.should.equal(authorizationCode);
        })
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: authorization code is invalid");
        });
    });

    it("should support promises", () => {
      const authorizationCode = { authorizationCode: 12345, client: {}, expiresAt: new Date(new Date() / 2), user: {} };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return Promise.resolve(true);
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.revokeAuthorizationCode(authorizationCode).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const authorizationCode = { authorizationCode: 12345, client: {}, expiresAt: new Date(new Date() / 2), user: {} };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {
          return authorizationCode;
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.revokeAuthorizationCode(authorizationCode).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const authorizationCode = { authorizationCode: 12345, client: {}, expiresAt: new Date(new Date() / 2), user: {} };
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode(code, callback) {
          callback(null, authorizationCode);
        },
        saveToken() {},
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.revokeAuthorizationCode(authorizationCode).should.be.an.instanceOf(Promise);
    });
  });

  describe("saveToken()", () => {
    it("should save the token", () => {
      const token = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {
          return token;
        },
        validateScope() {
          return "foo";
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .saveToken(token)
        .then((data) => {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const token = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {
          return Promise.resolve(token);
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const token = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken() {
          return token;
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const token = {};
      const model = {
        getAuthorizationCode() {},
        revokeAuthorizationCode() {},
        saveToken(tokenToSave, client, user, callback) {
          callback(null, token);
        },
      };
      const grantType = new AuthorizationCodeGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });
  });
});
