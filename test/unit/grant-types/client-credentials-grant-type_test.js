/* eslint-disable no-empty-function */
"use strict";

/**
 * Module dependencies.
 */

const ClientCredentialsGrantType = require("../../../lib/grant-types/client-credentials-grant-type");
const sinon = require("sinon");
const should = require("should");

/**
 * Test `ClientCredentialsGrantType`.
 */

describe("ClientCredentialsGrantType", () => {
  describe("getUserFromClient()", () => {
    it("should call `model.getUserFromClient()`", () => {
      const model = {
        getUserFromClient: sinon.stub().returns(true),
        saveToken() {},
      };
      const handler = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });
      const client = {};

      return handler
        .getUserFromClient(client)
        .then(() => {
          model.getUserFromClient.callCount.should.equal(1);
          model.getUserFromClient.firstCall.args.should.have.length(1);
          model.getUserFromClient.firstCall.args[0].should.equal(client);
          model.getUserFromClient.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });

  describe("saveToken()", () => {
    it("should call `model.saveToken()`", () => {
      const client = {};
      const user = {};
      const model = {
        getUserFromClient() {},
        saveToken: sinon.stub().returns(true),
      };
      const handler = new ClientCredentialsGrantType({ accessTokenLifetime: 120, model });

      sinon.stub(handler, "validateScope").returns("foobar");
      sinon.stub(handler, "generateAccessToken").returns("foo");
      sinon.stub(handler, "getAccessTokenExpiresAt").returns("biz");

      return handler
        .saveToken(user, client, "foobar")
        .then(() => {
          model.saveToken.callCount.should.equal(1);
          model.saveToken.firstCall.args.should.have.length(3);
          model.saveToken.firstCall.args[0].should.eql({
            accessToken: "foo",
            accessTokenExpiresAt: "biz",
            scope: "foobar",
          });
          model.saveToken.firstCall.args[1].should.equal(client);
          model.saveToken.firstCall.args[2].should.equal(user);
          model.saveToken.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });
  });
});
