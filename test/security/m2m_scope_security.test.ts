import * as jose from "jose";
import { M2M } from "../../lib/b2c/m2m";
import { ClientError } from "../../lib/shared/errors";
import { MOCK_FETCH_CONFIG } from "../helpers";

describe("M2M scope authorization security regression", () => {
  it("does not treat a longer required scope as equivalent to a shorter token scope", async () => {
    const keyID = "security-test-key";
    const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
    const jwk = await jose.exportJWK(publicKey);
    const jwks = jose.createLocalJWKSet({ keys: [{ ...jwk, kid: keyID }] });
    const projectID = "project-test-security-audit";
    const now = Math.floor(Date.now() / 1000);

    const m2m = new M2M(MOCK_FETCH_CONFIG, {
      projectID,
      jwks,
      issuers: [`stytch.com/${projectID}`],
    });

    const token = await new jose.SignJWT({
      sub: "m2m-client-security-test",
      scope: "read:users",
    })
      .setProtectedHeader({ alg: "RS256", kid: keyID, typ: "JWT" })
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + 300)
      .setIssuer(`stytch.com/${projectID}`)
      .setAudience([projectID])
      .sign(privateKey);

    await expect(
      m2m.authenticateToken({
        access_token: token,
        required_scopes: ["read:users:delete"],
      })
    ).rejects.toBeInstanceOf(ClientError);
  });

  it("does not let a malformed wildcard scope satisfy a longer required scope", async () => {
    const keyID = "security-test-key";
    const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
    const jwk = await jose.exportJWK(publicKey);
    const jwks = jose.createLocalJWKSet({ keys: [{ ...jwk, kid: keyID }] });
    const projectID = "project-test-security-audit";
    const now = Math.floor(Date.now() / 1000);
    const m2m = new M2M(MOCK_FETCH_CONFIG, {
      projectID,
      jwks,
      issuers: [`stytch.com/${projectID}`],
    });
    const token = await new jose.SignJWT({
      sub: "m2m-client-security-test",
      scope: "read:*:metadata",
    })
      .setProtectedHeader({ alg: "RS256", kid: keyID, typ: "JWT" })
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + 300)
      .setIssuer(`stytch.com/${projectID}`)
      .setAudience([projectID])
      .sign(privateKey);

    await expect(
      m2m.authenticateToken({
        access_token: token,
        required_scopes: ["read:users:delete"],
      })
    ).rejects.toBeInstanceOf(ClientError);
  });
});
