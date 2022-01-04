/* eslint-disable no-new */
"use strict";

/**
 * Module dependencies.
 */

const BearerTokenType = require("../../../lib/token-types/bearer-token-type");
const InvalidArgumentError = require("../../../lib/errors/invalid-argument-error");
const should = require("should");

/**
 * Test `BearerTokenType` integration.
 */

describe("BearerTokenType integration", () => {
  describe("constructor()", () => {
    it("should throw an error if `accessToken` is missing", () => {
      try {
        new BearerTokenType();

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal("Missing parameter: `accessToken`");
      }
    });

    it("should set the `accessToken`", () => {
      const responseType = new BearerTokenType("foo", "bar");

      responseType.accessToken.should.equal("foo");
    });

    it("should set the `accessTokenLifetime`", () => {
      const responseType = new BearerTokenType("foo", "bar");

      responseType.accessTokenLifetime.should.equal("bar");
    });

    it("should set the `refreshToken`", () => {
      const responseType = new BearerTokenType("foo", "bar", "biz");

      responseType.refreshToken.should.equal("biz");
    });
  });

  describe("valueOf()", () => {
    it("should return the value representation", () => {
      const responseType = new BearerTokenType("foo", "bar");
      const value = responseType.valueOf();

      value.should.eql({
        access_token: "foo",
        expires_in: "bar",
        token_type: "Bearer",
      });
    });

    it("should not include the `expires_in` if not given", () => {
      const responseType = new BearerTokenType("foo");
      const value = responseType.valueOf();

      value.should.eql({
        access_token: "foo",
        token_type: "Bearer",
      });
    });

    it("should set `refresh_token` if `refreshToken` is defined", () => {
      const responseType = new BearerTokenType("foo", "bar", "biz");
      const value = responseType.valueOf();

      value.should.eql({
        access_token: "foo",
        expires_in: "bar",
        refresh_token: "biz",
        token_type: "Bearer",
      });
    });

    it("should set `expires_in` if `accessTokenLifetime` is defined", () => {
      const responseType = new BearerTokenType("foo", "bar", "biz");
      const value = responseType.valueOf();

      value.should.eql({
        access_token: "foo",
        expires_in: "bar",
        refresh_token: "biz",
        token_type: "Bearer",
      });
    });
  });
});
