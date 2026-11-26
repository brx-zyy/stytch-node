import * as jose from "jose";
import { IDP as B2CIDP } from "../../lib/b2c/idp";
import { IDP as B2BIDP } from "../../lib/b2b/idp";
import { MOCK_FETCH_CONFIG } from "../helpers";

describe("IDP local token-type separation", () => {
  async function makeSignedSessionJWT(b2b: boolean) {
    const kid = "token-confusion-test";
    const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
    const jwk = await jose.exportJWK(publicKey);
    const jwks = jose.createLocalJWKSet({ keys: [{ ...jwk, kid }] });
    const projectID = "project-test-token-confusion";
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      sub: "user-session-subject",
      "https://stytch.com/session": {
        id: "session-test",
        started_at: new Date(now * 1000).toISOString(),
        last_accessed_at: new Date(now * 1000).toISOString(),
        expires_at: new Date((now + 300) * 1000).toISOString(),
        attributes: {},
        authentication_factors: [],
        roles: [],
      },
    };
    if (b2b) {
      payload["https://stytch.com/organization"] = {
        organization_id: "org-test",
        slug: "org-test",
      };
    }
    const token = await new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + 300)
      .setIssuer(`stytch.com/${projectID}`)
      .setAudience([projectID])
      .sign(privateKey);
    return {
      token,
      jwtConfig: {
        projectID,
        jwks,
        issuers: [`stytch.com/${projectID}`],
      },
    };
  }

  it("B2C local introspection accepts a session JWT as an access token", async () => {
    const { token, jwtConfig } = await makeSignedSessionJWT(false);
    const idp = new B2CIDP(MOCK_FETCH_CONFIG, jwtConfig, {} as any);
    const result = await idp.introspectTokenLocal(token);
    expect(result.token_type).toBe("access_token");
    expect(result.subject).toBe("user-session-subject");
    expect(result.scope).toBeUndefined();
  });

  it("B2B local introspection accepts a member-session JWT as an access token", async () => {
    const { token, jwtConfig } = await makeSignedSessionJWT(true);
    const idp = new B2BIDP(MOCK_FETCH_CONFIG, jwtConfig, {} as any);
    const result = await idp.introspectTokenLocal(token);
    expect(result.token_type).toBe("access_token");
    expect(result.subject).toBe("user-session-subject");
    expect(result.scope).toBeUndefined();
    expect(result.organization.organization_id).toBe("org-test");
  });
});
