/* eslint-disable func-names */
/* eslint-disable no-new */
"use strict";

/**
 * Module dependencies.
 */

const InvalidArgumentError = require("../../lib/errors/invalid-argument-error");
const Request = require("../../lib/request");
const Response = require("../../lib/response");
const Server = require("../../lib/server");
const should = require("should");

/**
 * Test `Server` integration.
 */

describe("Server integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `model` is missing", () => {
      try {
        new Server({});

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `model`");
      }
    });

    it("should set the `model`", () => {
      const model = {};
      const server = new Server({ model });

      server.options.model.should.equal(model);
    });
  });

  describe("authenticate()", () => {
    it("should set the default `options`", () => {
      const model = {
        getAccessToken() {
          return {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
      };
      const server = new Server({ model });
      const request = new Request({ body: {}, headers: { Authorization: "Bearer foo" }, method: {}, query: {} });
      const response = new Response({ body: {}, headers: {} });

      return server
        .authenticate(request, response)
        .then(function () {
          this.addAcceptedScopesHeader.should.be.true;
          this.addAuthorizedScopesHeader.should.be.true;
          this.allowBearerTokensInQueryString.should.be.false;
        })
        .catch(should.fail);
    });

    it("should return a promise", () => {
      const model = {
        getAccessToken(token, callback) {
          callback(null, {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          });
        },
      };
      const server = new Server({ model });
      const request = new Request({ body: {}, headers: { Authorization: "Bearer foo" }, method: {}, query: {} });
      const response = new Response({ body: {}, headers: {} });
      const handler = server.authenticate(request, response);

      handler.should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", (next) => {
      const model = {
        getAccessToken() {
          return {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
      };
      const server = new Server({ model });
      const request = new Request({ body: {}, headers: { Authorization: "Bearer foo" }, method: {}, query: {} });
      const response = new Response({ body: {}, headers: {} });

      server.authenticate(request, response, null, next);
    });
  });

  describe("authorize()", () => {
    it("should set the default `options`", () => {
      const model = {
        getAccessToken() {
          return {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
        },
        saveAuthorizationCode() {
          return { authorizationCode: 123 };
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: { client_id: 1234, client_secret: "secret", response_type: "code" },
        headers: { Authorization: "Bearer foo" },
        method: {},
        query: { state: "foobar" },
      });
      const response = new Response({ body: {}, headers: {} });

      return server
        .authorize(request, response)
        .then(function () {
          this.allowEmptyState.should.be.false;
          this.authorizationCodeLifetime.should.equal(300);
        })
        .catch(should.fail);
    });

    it("should return a promise", () => {
      const model = {
        getAccessToken() {
          return {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
        },
        saveAuthorizationCode() {
          return { authorizationCode: 123 };
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: { client_id: 1234, client_secret: "secret", response_type: "code" },
        headers: { Authorization: "Bearer foo" },
        method: {},
        query: { state: "foobar" },
      });
      const response = new Response({ body: {}, headers: {} });
      const handler = server.authorize(request, response);

      handler.should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", (next) => {
      const model = {
        getAccessToken() {
          return {
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
        },
        saveAuthorizationCode() {
          return { authorizationCode: 123 };
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: { client_id: 1234, client_secret: "secret", response_type: "code" },
        headers: { Authorization: "Bearer foo" },
        method: {},
        query: { state: "foobar" },
      });
      const response = new Response({ body: {}, headers: {} });

      server.authorize(request, response, null, next);
    });
  });

  describe("token()", () => {
    it.only("should set the default `options`", () => {
      const model = {
        getClient() {
          return { grants: ["password"] };
        },
        getUser() {
          return {};
        },
        saveToken() {
          return { accessToken: 1234, client: {}, user: {} };
        },
        validateScope() {
          return "foo";
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: {
          client_id: 1234,
          client_secret: "secret",
          grant_type: "password",
          username: "foo",
          password: "pass",
          scope: "foo",
        },
        headers: { "content-type": "application/x-www-form-urlencoded", "transfer-encoding": "chunked" },
        method: "POST",
        query: {},
      });
      const response = new Response({ body: {}, headers: {} });

      return server
        .token(request, response)
        .then(function () {
          console.log(this);
          this.accessTokenLifetime.should.equal(3600);
          this.refreshTokenLifetime.should.equal(1209600);
        })
        .catch(should.fail);
    });

    it("should return a promise", () => {
      const model = {
        getClient() {
          return { grants: ["password"] };
        },
        getUser() {
          return {};
        },
        saveToken() {
          return { accessToken: 1234, client: {}, user: {} };
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: { client_id: 1234, client_secret: "secret", grant_type: "password", username: "foo", password: "pass" },
        headers: { "content-type": "application/x-www-form-urlencoded", "transfer-encoding": "chunked" },
        method: "POST",
        query: {},
      });
      const response = new Response({ body: {}, headers: {} });
      const handler = server.token(request, response);

      handler.should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", (next) => {
      const model = {
        getClient() {
          return { grants: ["password"] };
        },
        getUser() {
          return {};
        },
        saveToken() {
          return { accessToken: 1234, client: {}, user: {} };
        },
        validateScope() {
          return "foo";
        },
      };
      const server = new Server({ model });
      const request = new Request({
        body: {
          client_id: 1234,
          client_secret: "secret",
          grant_type: "password",
          username: "foo",
          password: "pass",
          scope: "foo",
        },
        headers: { "content-type": "application/x-www-form-urlencoded", "transfer-encoding": "chunked" },
        method: "POST",
        query: {},
      });
      const response = new Response({ body: {}, headers: {} });

      server.token(request, response, null, next);
    });
  });
});
