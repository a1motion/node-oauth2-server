/* eslint-disable no-new */
"use strict";

/**
 * Module dependencies.
 */

const CodeResponseType = require("../../../lib/response-types/code-response-type");
const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const should = require("should");
const url = require("url");

/**
 * Test `CodeResponseType` integration.
 */

describe("CodeResponseType integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `code` is missing", () => {
      try {
        new CodeResponseType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `code`");
      }
    });

    it("should set the `code`", () => {
      const responseType = new CodeResponseType("foo");

      responseType.code.should.equal("foo");
    });
  });

  describe("buildRedirectUri()", () => {
    it("should throw an error if the `redirectUri` is missing", () => {
      const responseType = new CodeResponseType("foo");

      try {
        responseType.buildRedirectUri();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `redirectUri`");
      }
    });

    it("should return the new redirect uri and set the `code` and `state` in the query", () => {
      const responseType = new CodeResponseType("foo");
      const redirectUri = responseType.buildRedirectUri("http://example.com/cb");

      url.format(redirectUri).should.equal("http://example.com/cb?code=foo");
    });

    it("should return the new redirect uri and append the `code` and `state` in the query", () => {
      const responseType = new CodeResponseType("foo");
      const redirectUri = responseType.buildRedirectUri("http://example.com/cb?foo=bar");

      url.format(redirectUri).should.equal("http://example.com/cb?foo=bar&code=foo");
    });
  });
});
