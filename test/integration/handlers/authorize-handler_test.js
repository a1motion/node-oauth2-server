/* eslint-disable no-empty-function */
/* eslint-disable no-new */
"use strict";

/**
 * Module dependencies.
 */

const AccessDeniedError = require("../../../lib/errors/access-denied-error");
const AuthenticateHandler = require("../../../lib/handlers/authenticate-handler");
const AuthorizeHandler = require("../../../lib/handlers/authorize-handler");
const CodeResponseType = require("../../../lib/response-types/code-response-type");
const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const InvalidClientError = require("../../../lib/errors/invalid-client-error");
const InvalidRequestError = require("../../../lib/errors/invalid-request-error");
const InvalidScopeError = require("../../../lib/errors/invalid-scope-error");
const UnsupportedResponseTypeError = require("../../../lib/errors/unsupported-response-type-error");
const Request = require("../../../lib/request");
const Response = require("../../../lib/response");
const ServerError = require("../../../lib/errors/server-error");
const UnauthorizedClientError = require("../../../lib/errors/unauthorized-client-error");
const should = require("should");
const url = require("url");

/**
 * Test `AuthorizeHandler` integration.
 */

describe("AuthorizeHandler integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `options.authorizationCodeLifetime` is missing", () => {
      try {
        new AuthorizeHandler();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `authorizationCodeLifetime`");
      }
    });

    it("should throw an error if `options.model` is missing", () => {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120 });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `model`");
      }
    });

    it("should throw an error if the model does not implement `getClient()`", () => {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model: {} });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `getClient()`");
      }
    });

    it("should throw an error if the model does not implement `saveAuthorizationCode()`", () => {
      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model: { getClient() {} } });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `saveAuthorizationCode()`");
      }
    });

    it("should throw an error if the model does not implement `getAccessToken()`", () => {
      const model = {
        getClient() {},
        saveAuthorizationCode() {},
      };

      try {
        new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Invalid argument: model does not implement `getAccessToken()`");
      }
    });

    it("should set the `authorizationCodeLifetime`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.authorizationCodeLifetime.should.equal(120);
    });

    it("should set the `authenticateHandler`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.authenticateHandler.should.be.an.instanceOf(AuthenticateHandler);
    });

    it("should set the `model`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.model.should.equal(model);
    });
  });

  describe("handle()", () => {
    it("should throw an error if `request` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      return handler
        .handle()
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Invalid argument: `request` must be an instance of Request");
        });
    });

    it("should throw an error if `response` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      return handler
        .handle(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidArgumentError);
          e.message.should.equal("Invalid argument: `response` must be an instance of Response");
        });
    });

    it("should throw an error if `allowed` is `false`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: { allowed: "false" } });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(AccessDeniedError);
          e.message.should.equal("Access denied: user denied access to application");
        });
    });

    it("should redirect to an error response if a non-oauth error is thrown", () => {
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
          throw new Error("Unhandled exception");
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=server_error&error_description=Unhandled%20exception&state=foobar"
            );
        });
    });

    it("should redirect to an error response if an oauth error is thrown", () => {
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
          throw new AccessDeniedError("Cannot request this auth code");
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=access_denied&error_description=Cannot%20request%20this%20auth%20code&state=foobar"
            );
        });
    });

    it("should redirect to a successful response with `code` and `state` if successful", () => {
      const client = { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
      const model = {
        getAccessToken() {
          return {
            client,
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return client;
        },
        saveAuthorizationCode() {
          return { authorizationCode: 12345, client };
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(() => {
          response.get("location").should.equal("http://example.com/cb?code=12345&state=foobar");
        })
        .catch(should.fail);
    });

    it("should redirect to an error response if `scope` is invalid", () => {
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
          return {};
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          scope: [],
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=invalid_scope&error_description=Invalid%20parameter%3A%20%60scope%60"
            );
        });
    });

    it("should redirect to a successful response if `model.validateScope` is not defined", () => {
      const client = { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
      const model = {
        getAccessToken() {
          return {
            client,
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return client;
        },
        saveAuthorizationCode() {
          return { authorizationCode: 12345, client };
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          scope: "read",
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then((data) => {
          data.should.eql({
            authorizationCode: 12345,
            client,
          });
        })
        .catch(should.fail);
    });

    it("should redirect to an error response if `scope` is insufficient", () => {
      const client = { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
      const model = {
        getAccessToken() {
          return {
            client,
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return client;
        },
        saveAuthorizationCode() {
          return { authorizationCode: 12345, client };
        },
        validateScope() {
          return false;
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          scope: "read",
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=invalid_scope&error_description=Invalid%20scope%3A%20Requested%20scope%20is%20invalid"
            );
        });
    });

    it("should redirect to an error response if `state` is missing", () => {
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
          throw new AccessDeniedError("Cannot request this auth code");
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {},
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=invalid_request&error_description=Missing%20parameter%3A%20%60state%60"
            );
        });
    });

    it("should redirect to an error response if `response_type` is invalid", () => {
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
          return { authorizationCode: 12345, client: {} };
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "test",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=unsupported_response_type&error_description=Unsupported%20response%20type%3A%20%60response_type%60%20is%20not%20supported&state=foobar"
            );
        });
    });

    it("should fail on invalid `response_type` before calling model.saveAuthorizationCode()", () => {
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
          throw new Error("must not be reached");
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "test",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then(should.fail)
        .catch(() => {
          response
            .get("location")
            .should.equal(
              "http://example.com/cb?error=unsupported_response_type&error_description=Unsupported%20response%20type%3A%20%60response_type%60%20is%20not%20supported&state=foobar"
            );
        });
    });

    it("should return the `code` if successful", () => {
      const client = { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
      const model = {
        getAccessToken() {
          return {
            client,
            user: {},
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {
          return client;
        },
        saveAuthorizationCode() {
          return { authorizationCode: 12345, client };
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: {
          client_id: 12345,
          response_type: "code",
        },
        headers: {
          Authorization: "Bearer foo",
        },
        method: {},
        query: {
          state: "foobar",
        },
      });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .handle(request, response)
        .then((data) => {
          data.should.eql({
            authorizationCode: 12345,
            client,
          });
        })
        .catch(should.fail);
    });
  });

  describe("generateAuthorizationCode()", () => {
    it("should return an auth code", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      return handler
        .generateAuthorizationCode()
        .then((data) => {
          data.should.be.a.sha1;
        })
        .catch(should.fail);
    });

    it("should support promises", () => {
      const model = {
        generateAuthorizationCode() {
          return Promise.resolve({});
        },
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const model = {
        generateAuthorizationCode() {
          return {};
        },
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.generateAuthorizationCode().should.be.an.instanceOf(Promise);
    });
  });

  describe("getAuthorizationCodeLifetime()", () => {
    it("should return a date", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.getAuthorizationCodeLifetime().should.be.an.instanceOf(Date);
    });
  });

  describe("getClient()", () => {
    it("should throw an error if `client_id` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: { response_type: "code" }, headers: {}, method: {}, query: {} });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `client_id`");
      }
    });

    it("should throw an error if `client_id` is invalid", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: "øå€£‰", response_type: "code" },
        headers: {},
        method: {},
        query: {},
      });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid parameter: `client_id`");
      }
    });

    it("should throw an error if `client.redirectUri` is invalid", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code", redirect_uri: "foobar" },
        headers: {},
        method: {},
        query: {},
      });

      try {
        handler.getClient(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid request: `redirect_uri` is not a valid URI");
      }
    });

    it("should throw an error if `client` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code" },
        headers: {},
        method: {},
        query: {},
      });

      return handler
        .getClient(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal("Invalid client: client credentials are invalid");
        });
    });

    it("should throw an error if `client.grants` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return {};
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code" },
        headers: {},
        method: {},
        query: {},
      });

      return handler
        .getClient(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal("Invalid client: missing client `grants`");
        });
    });

    it("should throw an error if `client` is unauthorized", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return { grants: [] };
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code" },
        headers: {},
        method: {},
        query: {},
      });

      return handler
        .getClient(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(UnauthorizedClientError);
          e.message.should.equal("Unauthorized client: `grant_type` is invalid");
        });
    });

    it("should throw an error if `client.redirectUri` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return { grants: ["authorization_code"] };
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code" },
        headers: {},
        method: {},
        query: {},
      });

      return handler
        .getClient(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal("Invalid client: missing client `redirectUri`");
        });
    });

    it("should throw an error if `client.redirectUri` is not equal to `redirectUri`", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return { grants: ["authorization_code"], redirectUris: ["https://example.com"] };
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345, response_type: "code", redirect_uri: "https://foobar.com" },
        headers: {},
        method: {},
        query: {},
      });

      return handler
        .getClient(request)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(InvalidClientError);
          e.message.should.equal("Invalid client: `redirect_uri` does not match client value");
        });
    });

    it("should support promises", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return Promise.resolve({ grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] });
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345 },
        headers: {},
        method: {},
        query: {},
      });

      handler.getClient(request).should.be.an.instanceOf(Promise);
    });

    it("should support non-promises", () => {
      const model = {
        getAccessToken() {},
        getClient() {
          return { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345 },
        headers: {},
        method: {},
        query: {},
      });

      handler.getClient(request).should.be.an.instanceOf(Promise);
    });

    it("should support callbacks", () => {
      const model = {
        getAccessToken() {},
        getClient(clientId, clientSecret, callback) {
          should.equal(clientSecret, null);
          callback(null, { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] });
        },
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({
        body: { client_id: 12345 },
        headers: {},
        method: {},
        query: {},
      });

      handler.getClient(request).should.be.an.instanceOf(Promise);
    });

    describe("with `client_id` in the request query", () => {
      it("should return a client", () => {
        const client = { grants: ["authorization_code"], redirectUris: ["http://example.com/cb"] };
        const model = {
          getAccessToken() {},
          getClient() {
            return client;
          },
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({
          body: { response_type: "code" },
          headers: {},
          method: {},
          query: { client_id: 12345 },
        });

        return handler
          .getClient(request)
          .then((data) => {
            data.should.equal(client);
          })
          .catch(should.fail);
      });
    });
  });

  describe("getScope()", () => {
    it("should throw an error if `scope` is invalid", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: { scope: "øå€£‰" }, headers: {}, method: {}, query: {} });

      try {
        handler.getScope(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidScopeError);
        e.message.should.equal("Invalid parameter: `scope`");
      }
    });

    describe("with `scope` in the request body", () => {
      it("should return the scope", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: { scope: "foo" }, headers: {}, method: {}, query: {} });

        handler.getScope(request).should.equal("foo");
      });
    });

    describe("with `scope` in the request query", () => {
      it("should return the scope", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: {}, headers: {}, method: {}, query: { scope: "foo" } });

        handler.getScope(request).should.equal("foo");
      });
    });
  });

  describe("getState()", () => {
    it("should throw an error if `allowEmptyState` is false and `state` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ allowEmptyState: false, authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        handler.getState(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `state`");
      }
    });

    it("should throw an error if `state` is invalid", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: { state: "øå€£‰" } });

      try {
        handler.getState(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Invalid parameter: `state`");
      }
    });

    describe("with `state` in the request body", () => {
      it("should return the state", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: { state: "foobar" }, headers: {}, method: {}, query: {} });

        handler.getState(request).should.equal("foobar");
      });
    });

    describe("with `state` in the request query", () => {
      it("should return the state", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: {}, headers: {}, method: {}, query: { state: "foobar" } });

        handler.getState(request).should.equal("foobar");
      });
    });
  });

  describe("getUser()", () => {
    it("should throw an error if `user` is missing", () => {
      const authenticateHandler = { handle() {} };
      const model = {
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({
        authenticateHandler,
        authorizationCodeLifetime: 120,
        model,
      });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });
      const response = new Response();

      return handler
        .getUser(request, response)
        .then(should.fail)
        .catch((e) => {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal("Server error: `handle()` did not return a `user` object");
        });
    });

    it("should return a user", () => {
      const user = {};
      const model = {
        getAccessToken() {
          return {
            user,
            accessTokenExpiresAt: new Date(new Date().getTime() + 10000),
          };
        },
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: { Authorization: "Bearer foo" }, method: {}, query: {} });
      const response = new Response({ body: {}, headers: {} });

      return handler
        .getUser(request, response)
        .then((data) => {
          data.should.equal(user);
        })
        .catch(should.fail);
    });
  });

  describe("saveAuthorizationCode()", () => {
    it("should return an auth code", () => {
      const authorizationCode = {};
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {
          return authorizationCode;
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      return handler
        .saveAuthorizationCode("foo", "bar", "biz", "baz")
        .then((data) => {
          data.should.equal(authorizationCode);
        })
        .catch(should.fail);
    });

    it("should support promises when calling `model.saveAuthorizationCode()`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {
          return Promise.resolve({});
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.saveAuthorizationCode("foo", "bar", "biz", "baz").should.be.an.instanceOf(Promise);
    });

    it("should support non-promises when calling `model.saveAuthorizationCode()`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {
          return {};
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.saveAuthorizationCode("foo", "bar", "biz", "baz").should.be.an.instanceOf(Promise);
    });

    it("should support callbacks when calling `model.saveAuthorizationCode()`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode(code, client, user, callback) {
          return callback(null, true);
        },
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });

      handler.saveAuthorizationCode("foo", "bar", "biz", "baz").should.be.an.instanceOf(Promise);
    });
  });

  describe("getResponseType()", () => {
    it("should throw an error if `response_type` is missing", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: {}, headers: {}, method: {}, query: {} });

      try {
        handler.getResponseType(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal("Missing parameter: `response_type`");
      }
    });

    it("should throw an error if `response_type` is not `code`", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const request = new Request({ body: { response_type: "foobar" }, headers: {}, method: {}, query: {} });

      try {
        handler.getResponseType(request);

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(UnsupportedResponseTypeError);
        e.message.should.equal("Unsupported response type: `response_type` is not supported");
      }
    });

    describe("with `response_type` in the request body", () => {
      it("should return a response type", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: { response_type: "code" }, headers: {}, method: {}, query: {} });
        const ResponseType = handler.getResponseType(request);

        ResponseType.should.equal(CodeResponseType);
      });
    });

    describe("with `response_type` in the request query", () => {
      it("should return a response type", () => {
        const model = {
          getAccessToken() {},
          getClient() {},
          saveAuthorizationCode() {},
        };
        const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
        const request = new Request({ body: {}, headers: {}, method: {}, query: { response_type: "code" } });
        const ResponseType = handler.getResponseType(request);

        ResponseType.should.equal(CodeResponseType);
      });
    });
  });

  describe("buildSuccessRedirectUri()", () => {
    it("should return a redirect uri", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const responseType = new CodeResponseType(12345);
      const redirectUri = handler.buildSuccessRedirectUri("http://example.com/cb", responseType);

      url.format(redirectUri).should.equal("http://example.com/cb?code=12345");
    });
  });

  describe("buildErrorRedirectUri()", () => {
    it("should set `error_description` if available", () => {
      const error = new InvalidClientError("foo bar");
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const redirectUri = handler.buildErrorRedirectUri("http://example.com/cb", error);

      url.format(redirectUri).should.equal("http://example.com/cb?error=invalid_client&error_description=foo%20bar");
    });

    it("should return a redirect uri", () => {
      const error = new InvalidClientError();
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const redirectUri = handler.buildErrorRedirectUri("http://example.com/cb", error);

      url
        .format(redirectUri)
        .should.equal("http://example.com/cb?error=invalid_client&error_description=Bad%20Request");
    });
  });

  describe("updateResponse()", () => {
    it("should set the `location` header", () => {
      const model = {
        getAccessToken() {},
        getClient() {},
        saveAuthorizationCode() {},
      };
      const handler = new AuthorizeHandler({ authorizationCodeLifetime: 120, model });
      const response = new Response({ body: {}, headers: {} });
      const uri = url.parse("http://example.com/cb");

      handler.updateResponse(response, uri, "foobar");

      response.get("location").should.equal("http://example.com/cb?state=foobar");
    });
  });
});
