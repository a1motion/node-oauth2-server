/* eslint-disable no-new */
/* eslint-disable no-empty-function */
"use strict";

/**
 * Module dependencies.
 */

const ClientCredentialsGrantType = require("../../../lib/grant-types/client-credentials-grant-type");
const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const InvalidGrantError = require("../../../lib/errors/invalid-grant-error");
const Request = require("../../../lib/request");
const should = require("should");

/**
 * Test `ClientCredentialsGrantType` integration.
 */

describe("ClientCredentialsGrantType integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `model` is missing", () => {
      try {
        new ClientCredentialsGrantType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `model`");
      }
    });

    it("should throw an error if the model does not implement `getUserFromClient()`", () => {
      try {
        new ClientCredentialsGrantType({ model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `getUserFromClient()`");
      }
    });

    it("should throw an error if the model does not implement `saveToken()`", () => {
      try {
        const model = {
          getUserFromClient() {},
        };

        new ClientCredentialsGrantType({ model });

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
        getUserFromClient() {},
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });

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
        getUserFromClient() {},
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      return grantType
        .handle(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Missing parameter: `client`");
        });
    });

    it("should return a token", () => {
      const token = {};
      const model = {
        getUserFromClient() {
          return {};
        },
        saveToken() {
          return token;
        },
        validateScope() {
          return "foo";
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      return grantType
        .handle(request, {})
        .then((data) => {
          data.should.equal(token);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const token = {};
      const model = {
        getUserFromClient() {
          return {};
        },
        saveToken() {
          return token;
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      grantType.handle(request, {}).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const token = {};
      const model = {
        getUserFromClient() {
          return {};
        },
        saveToken() {
          return token;
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      grantType.handle(request, {}).should.be.an.instanceOf(Promise);
    });
  });

  describe("getUserFromClient()", () => {
    it("should throw an error if `user` is missing", () => {
      const model = {
        getUserFromClient() {},
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      return grantType
        .getUserFromClient(request, {})
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidGrantError);
          e.message.should.equal("Invalid grant: user credentials are invalid");
        });
    });

    it("should return a user", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUserFromClient() {
          return user;
        },
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      return grantType
        .getUserFromClient(request, {})
        .then((data) => {
          data.should.equal(user);
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUserFromClient() {
          return Promise.resolve(user);
        },
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      grantType.getUserFromClient(request, {}).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUserFromClient() {
          return user;
        },
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      grantType.getUserFromClient(request, {}).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const user = { email: "foo@bar.com" };
      const model = {
        getUserFromClient(userId, callback) {
          callback(null, user);
        },
        saveToken() {},
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      grantType.getUserFromClient(request, {}).should.be.an.instanceOf(Promise);
    });
  });

  describe("saveToken()", () => {
    it("should save the token", () => {
      const token = {};
      const model = {
        getUserFromClient() {},
        saveToken() {
          return token;
        },
        validateScope() {
          return "foo";
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 123, model });

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
        getUserFromClient() {},
        saveToken() {
          return Promise.resolve(token);
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const token = {};
      const model = {
        getUserFromClient() {},
        saveToken() {
          return token;
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const token = {};
      const model = {
        getUserFromClient() {},
        saveToken(tokenToSave, client, user, callback) {
          callback(null, token);
        },
      };
      const grantType = new ClientCredentialsGrantType({ accessTokenLifetime: 123, model });

      grantType.saveToken(token).should.be.an.instanceOf(Promise);
    });
  });
});
