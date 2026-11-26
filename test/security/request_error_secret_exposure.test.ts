import { RequestError } from "../../lib/shared/errors";

describe("RequestError sensitive request retention probe", () => {
  it("reproduces serialization of secrets retained in the request payload", () => {
    const error = new RequestError("network unavailable", {
      method: "POST",
      url: "/v1/b2b/passwords/authenticate",
      data: {
        email: "researcher@example.invalid",
        password: "test-password-secret",
        session_token: "test-session-token-secret",
      },
    });

    // RequestError exposes the original request config as an enumerable property.
    // Applications that JSON.stringify(error) or structured-log it will include these values.
    const serialized = JSON.stringify(error);
    expect(serialized).toContain("test-password-secret");
    expect(serialized).toContain("test-session-token-secret");
  });
});
