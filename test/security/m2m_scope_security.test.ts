import * as jose from "jose";
import { M2M } from "../../lib/b2c/m2m";
import { MOCK_FETCH_CONFIG } from "../helpers";

describe("M2M scope authorization security reproduction", () => {
  async function makeM2M(scope: string): Promise<{ m2m: M2M; token: string }> {
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
      scope,
    })
      .setProtectedHeader({ alg: "RS256", kid: keyID, typ: "JWT" })
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + 300)
      .setIssuer(`stytch.com/${projectID}`)
      .setAudience([projectID])
      .sign(privateKey);
    return { m2m, token };
  }

  it("reproduces: read:users satisfies required scope read:users:delete", async () => {
    const { m2m, token } = await makeM2M("read:users");
    const result = await m2m.authenticateToken({
      access_token: token,
      required_scopes: ["read:users:delete"],
    });
    expect(result.scopes).toEqual(["read:users"]);
  });

  it("reproduces: read:*:metadata satisfies required scope read:users:delete", async () => {
    const { m2m, token } = await makeM2M("read:*:metadata");
    const result = await m2m.authenticateToken({
      access_token: token,
      required_scopes: ["read:users:delete"],
    });
    expect(result.scopes).toEqual(["read:*:metadata"]);
  });
});
