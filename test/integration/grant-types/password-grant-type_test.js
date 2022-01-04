/* eslint-disable no-new */
/* eslint-disable no-empty-function */
"use strict";

/**
 * Module dependencies.
 */

const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const InvalidGrantError = require("../../../lib/errors/invalid-grant-error");
const InvalidRequestError = require("../../../lib/errors/invalid-request-error");
const PasswordGrantType = require("../../../lib/grant-types/password-grant-type");
const Request = require("../../../lib/request");
const should = require("should");

/**
 * Test `PasswordGrantType` integration.
 */

describe("PasswordGrantType integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `model` is missing", () => {
      try {
        new PasswordGrantType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `model`");
      }
    });

    it("should throw an error if the model does not implement `getUser()`", () => {
      try {
        new PasswordGrantType({ model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `getUser()`");
      }
    });

    it("should throw an error if the model does not implement `saveToken()`", () => {
      try {
        const model = {
          getUser() {},
        };

        new PasswordGrantType({ model });

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
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .handle()
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Missing parameter: `request`");
        });
    });

    it("should throw an error if `client` is missing", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

      return grantType
        .handle()
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Missing parameter: `client`");
        });
    });

    it("should return a token", () => {
      const client = { id: "foobar" };
      const token = {};
      const model = {
        getUser() {
          return {};
        },
        saveToken() {
          return token;
        },
        validateScope() {
          return "baz";
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({
        body: { username: "foo", password: "bar", scope: "baz" },
        headers: {},
        method: {},
        query: {},
      });

      return grantType
        .handle(request, client)
        .then((data) => {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const client = { id: "foobar" };
      const token = {};
      const model = {
        getUser() {
          return {};
        },
        saveToken() {
          return Promise.resolve(token);
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const client = { id: "foobar" };
      const token = {};
      const model = {
        getUser() {
          return {};
        },
        saveToken() {
          return token;
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const client = { id: "foobar" };
      const token = {};
      const model = {
        getUser(username, password, callback) {
          callback(null, {});
        },
        saveToken(tokenToSave, client, user, callback) {
          callback(null, token);
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.handle(request, client).should.be.an.instanceOf(Promise);
    });
  });

  describe("getUser()", () => {
    it("should throw an error if the request body does not contain `username`", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        grantType.getUser(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `username`");
      }
    });

    it("should throw an error if the request body does not contain `password`", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo" }, headers: {}, method: {}, query: {} });

      try {
        grantType.getUser(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `password`");
      }
    });

    it("should throw an error if `username` is invalid", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({
        body: { username: "\r\n", password: "foobar" },
        headers: {},
        method: {},
        query: {},
      });

      try {
        grantType.getUser(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid parameter: `username`");
      }
    });

    it("should throw an error if `password` is invalid", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({
        body: { username: "foobar", password: "\r\n" },
        headers: {},
        method: {},
        query: {},
      });

      try {
        grantType.getUser(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid parameter: `password`");
      }
    });

    it("should throw an error if `user` is missing", () => {
      const model = {
        getUser() {},
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      return grantType
        .getUser(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: user credentials are invalid");
        });
    });

    it("should return a user", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUser() {
          return user;
        },
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      return grantType
        .getUser(request)
        .then((data) => {
          data.should.equal(user);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUser() {
          return Promise.resolve(user);
        },
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.getUser(request).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUser() {
          return user;
        },
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.getUser(request).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUser(username, password, callback) {
          callback(null, user);
        },
        saveToken() {},
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });
      const request = new Request({ body: { username: "foo", password: "bar" }, headers: {}, method: {}, query: {} });

      grantType.getUser(request).should.be.an.instanceOf(Promise);
    });
  });

  describe("saveToken()", () => {
    it("should save the token", () => {
      const token = {};
      const model = {
        getUser() {},
        saveToken() {
          return token;
        },
        validateScope() {
          return "foo";
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

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
        getUser() {},
        saveToken() {
          return Promise.resolve(token);
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const token = {};
      const model = {
        getUser() {},
        saveToken() {
          return token;
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const token = {};
      const model = {
        getUser() {},
        saveToken(tokenToSave, client, user, callback) {
          callback(null, token);
        },
      };
      const grantType = new PasswordGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });
  });
});
