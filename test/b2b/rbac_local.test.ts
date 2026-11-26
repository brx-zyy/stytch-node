import {
  performAuthorizationCheck,
  performScopeAuthorizationCheck,
  PolicyCache,
} from "../../lib/b2b/rbac_local";
import { AuthorizationCheck, ClientError } from "../../lib";
import { MOCK_RBAC_POLICY } from "./rbac_policy";

describe("PolicyCache", () => {
  const organizationID = "org-123";
  const FAKE_POLICY = { FAKE: "POLICY" };
  const FAKE_POLICY_2 = { FAKE: "POLICY", TWO: "YES" };
  const FAKE_ORG_POLICY = { FAKE: "ORG_POLICY" };
  const FAKE_ORG_POLICY_2 = { FAKE: "ORG_POLICY", TWO: "YES" };

  let policyCache: PolicyCache;
  let policySpy: {
    policy: jest.Mock;
    organizations: { getOrgPolicy: jest.Mock };
  };
  beforeEach(() => {
    policySpy = {
      policy: jest.fn(),
      organizations: {
        getOrgPolicy: jest.fn(),
      },
    };

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    policyCache = new PolicyCache(policySpy);
    jest.useFakeTimers().setSystemTime(new Date("2023-10-05T00:00:00.000Z"));
  });

  it("Retrieves a policy and caches it locally", async () => {
    policySpy.policy.mockResolvedValue({ policy: FAKE_POLICY });
    const policy = await policyCache.getPolicy();
    expect(policy).toBe(FAKE_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(1);

    // 2 minutes later, we shouldn't refresh yet
    jest.setSystemTime(new Date("2023-10-05T00:02:00.000Z"));

    const policy2 = await policyCache.getPolicy();
    expect(policy2).toBe(FAKE_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(1);
  });

  it("Retrieves an org policy and caches it locally", async () => {
    policySpy.organizations.getOrgPolicy.mockResolvedValue({
      org_policy: FAKE_ORG_POLICY,
    });
    const orgPolicy = await policyCache.getOrgPolicy(organizationID);
    expect(orgPolicy).toBe(FAKE_ORG_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(0);
    expect(policySpy.organizations.getOrgPolicy).toHaveBeenCalledTimes(1);

    // 2 minutes later, we shouldn't refresh yet
    jest.setSystemTime(new Date("2023-10-05T00:02:00.000Z"));

    const orgPolicy2 = await policyCache.getOrgPolicy(organizationID);
    expect(orgPolicy2).toBe(FAKE_ORG_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(0);
    expect(policySpy.organizations.getOrgPolicy).toHaveBeenCalledTimes(1);
  });

  it("Updates the project policy cache after MAX_AGE_MS time elapses", async () => {
    policySpy.policy
      .mockResolvedValueOnce({ policy: FAKE_POLICY })
      .mockResolvedValueOnce({ policy: FAKE_POLICY_2 });
    const policy = await policyCache.getPolicy();
    expect(policy).toBe(FAKE_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(1);

    jest.setSystemTime(new Date("2023-10-05T00:10:01.000Z"));

    const policy2 = await policyCache.getPolicy();
    expect(policy2).toBe(FAKE_POLICY_2);
    expect(policySpy.policy).toHaveBeenCalledTimes(2);
  });

  it("shows an out-of-order project refresh can restore a revoked role permission", async () => {
    const stalePolicy = MOCK_RBAC_POLICY;
    const currentPolicy = {
      ...MOCK_RBAC_POLICY,
      roles: MOCK_RBAC_POLICY.roles.filter(
        (role) => role.role_id !== "editor"
      ),
    };
    let resolveStale: (value: { policy: typeof stalePolicy }) => void;
    let resolveCurrent: (value: { policy: typeof currentPolicy }) => void;
    const staleResponse = new Promise<{ policy: typeof stalePolicy }>(\n      (resolve) => {
      resolveStale = resolve;
    });
    const currentResponse = new Promise<{ policy: typeof currentPolicy }>(\n      (resolve) => {
      resolveCurrent = resolve;
    });

    policySpy.policy
      .mockReturnValueOnce(staleResponse)
      .mockReturnValueOnce(currentResponse);

    const staleRefresh = policyCache.getPolicy();
    const currentRefresh = policyCache.getPolicy();

    resolveCurrent!({ policy: currentPolicy });
    await currentRefresh;
    resolveStale!({ policy: stalePolicy });
    await staleRefresh;

    const cachedPolicy = await policyCache.getPolicy();
    expect(\n      cachedPolicy.roles.some((role) => role.role_id === "editor")\n    ).toBe(true);

    // The stale snapshot still grants the editor role permission to write documents.
    expect(() =>
      performAuthorizationCheck({
        policyRoles: cachedPolicy.roles,
        subjectRoles: ["editor"],
        subjectOrgID: organizationID,
        authorizationCheck: {
          organization_id: organizationID,
          resource_id: "documents",
          action: "write",
        },
      })
    ).not.toThrow();
  });

  it("reproduces an out-of-order organization-policy refresh", async () => {
    const staleOrgPolicy = { roles: MOCK_RBAC_POLICY.roles };
    const currentOrgPolicy = {
      roles: MOCK_RBAC_POLICY.roles.filter(\n        (role) => role.role_id !== "organization_admin"\n      ),
    };
    let resolveStale: (value: { org_policy: typeof staleOrgPolicy }) => void;
    let resolveCurrent: (value: { org_policy: typeof currentOrgPolicy }) => void;
    const staleResponse = new Promise<{ org_policy: typeof staleOrgPolicy }>((resolve) => {
      resolveStale = resolve;
    });
    const currentResponse = new Promise<{ org_policy: typeof currentOrgPolicy }>((resolve) => {
      resolveCurrent = resolve;
    });

    policySpy.organizations.getOrgPolicy
      .mockReturnValueOnce(staleResponse)
      .mockReturnValueOnce(currentResponse);

    const staleRefresh = policyCache.getOrgPolicy(organizationID);
    const currentRefresh = policyCache.getOrgPolicy(organizationID);

    resolveCurrent!({ org_policy: currentOrgPolicy });
    await currentRefresh;
    resolveStale!({ org_policy: staleOrgPolicy });
    await staleRefresh;

    const cached = await policyCache.getOrgPolicy(organizationID);
    expect(\n      cached.roles.some((role) => role.role_id === "organization_admin")\n    ).toBe(true);
    expect(policySpy.organizations.getOrgPolicy).toHaveBeenCalledTimes(2);
  });

  it("reproduces an out-of-order refresh overwriting a newer project policy", async () => {
    let resolveOlder: (value: { policy: typeof FAKE_POLICY }) => void;
    let resolveNewer: (value: { policy: typeof FAKE_POLICY_2 }) => void;
    const olderResponse = new Promise<{ policy: typeof FAKE_POLICY }>((resolve) => {
      resolveOlder = resolve;
    });
    const newerResponse = new Promise<{ policy: typeof FAKE_POLICY_2 }>((resolve) => {
      resolveNewer = resolve;
    });

    policySpy.policy
      .mockReturnValueOnce(olderResponse)
      .mockReturnValueOnce(newerResponse);

    // Two callers observe an expired/empty cache and start independent refreshes.
    const olderRefresh = policyCache.getPolicy();
    const newerRefresh = policyCache.getPolicy();

    // The newer server snapshot returns first, followed by the older snapshot.
    resolveNewer!({ policy: FAKE_POLICY_2 });
    await newerRefresh;
    resolveOlder!({ policy: FAKE_POLICY });
    await olderRefresh;

    // The older response overwrites the newer snapshot and is considered fresh for 5 minutes.
    await expect(policyCache.getPolicy()).resolves.toBe(FAKE_POLICY);
    expect(policySpy.policy).toHaveBeenCalledTimes(2);
  });

  it("Updates the org policy cache after MAX_AGE_MS time elapses", async () => {
    policySpy.organizations.getOrgPolicy
      .mockResolvedValueOnce({ org_policy: FAKE_ORG_POLICY })
      .mockResolvedValueOnce({ org_policy: FAKE_ORG_POLICY_2 });
    const policy = await policyCache.getOrgPolicy(organizationID);
    expect(policy).toBe(FAKE_ORG_POLICY);
    expect(policySpy.organizations.getOrgPolicy).toHaveBeenCalledTimes(1);

    jest.setSystemTime(new Date("2023-10-05T00:10:01.000Z"));

    const policy2 = await policyCache.getOrgPolicy(organizationID);
    expect(policy2).toBe(FAKE_ORG_POLICY_2);
    expect(policySpy.organizations.getOrgPolicy).toHaveBeenCalledTimes(2);
  });
});

describe("performAuthorizationCheck", () => {
  type testcase = {
    name: string;
    subjectRoles: string[];
    subjectOrgID: string;
    authorizationCheck: AuthorizationCheck;
    expectedError?: Error;
  };

  const testCases: testcase[] = [
    {
      name: "Success case - exact match",
      subjectRoles: ["default", "reader"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
    },
    {
      name: "Success case - wildcard match",
      subjectRoles: ["default", "organization_admin"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
    },
    {
      name: "Success case - multiple matches",
      subjectRoles: ["default", "reader", "editor", "organization_admin"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
    },
    {
      name: "Success case - multiple matches II",
      subjectRoles: ["default", "reader", "editor", "organization_admin"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "images",
        action: "create",
      },
    },
    {
      name: "Failure case - invalid action",
      subjectRoles: ["default", "editor"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "delete",
      },
      expectedError: new ClientError(
        "invalid_permissions",
        "Member does not have permission to perform the requested action"
      ),
    },
    {
      name: "Failure case - invalid resource",
      subjectRoles: ["default", "editor"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "images",
        action: "write",
      },
      expectedError: new ClientError(
        "invalid_permissions",
        "Member does not have permission to perform the requested action"
      ),
    },
    {
      name: "Failure case - invalid tenancy check",
      subjectRoles: ["default", "reader"],
      subjectOrgID: "organization-123",
      authorizationCheck: {
        organization_id: "organization-456",
        resource_id: "documents",
        action: "read",
      },
      expectedError: new ClientError(
        "tenancy_mismatch",
        "Member belongs to different organization"
      ),
    },
  ];

  testCases.forEach((tc) =>
    it(tc.name, () => {
      const fn = () =>
        performAuthorizationCheck({
          policyRoles: MOCK_RBAC_POLICY.roles,
          authorizationCheck: tc.authorizationCheck,
          subjectOrgID: tc.subjectOrgID,
          subjectRoles: tc.subjectRoles,
        });

      if (tc.expectedError) {
        expect(fn).toThrow(tc.expectedError);
      } else {
        expect(fn).not.toThrow();
      }
    })
  );
});

describe("performScopeAuthorizationCheck", () => {
  type testcase = {
    name: string;
    tokenScopes: string[];
    authorizationCheck: AuthorizationCheck;
    subjectOrgId: string;
    expectedError?: Error;
  };

  const testCases: testcase[] = [
    {
      name: "Success case - exact match",
      tokenScopes: ["read:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
      subjectOrgId: "organization-123",
    },
    {
      name: "Success case - wildcard match",
      tokenScopes: ["wildcard:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
      subjectOrgId: "organization-123",
    },
    {
      name: "Success case - multiple matches",
      tokenScopes: ["read:data", "write:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "read",
      },
      subjectOrgId: "organization-123",
    },
    {
      name: "Success case - multiple matches II",
      tokenScopes: ["read:data", "write:data", "crud:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "images",
        action: "create",
      },
      subjectOrgId: "organization-123",
    },
    {
      name: "Failure case - invalid action",
      tokenScopes: ["write:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "documents",
        action: "delete",
      },
      subjectOrgId: "organization-123",
      expectedError: new ClientError(
        "invalid_permissions",
        "Member does not have permission to perform the requested action"
      ),
    },
    {
      name: "Failure case - invalid resource",
      tokenScopes: ["crud:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "images",
        action: "write",
      },
      subjectOrgId: "organization-123",
      expectedError: new ClientError(
        "invalid_permissions",
        "Member does not have permission to perform the requested action"
      ),
    },
    {
      name: "Failure case - invalid tenancy check",
      tokenScopes: ["crud:data"],
      authorizationCheck: {
        organization_id: "organization-123",
        resource_id: "images",
        action: "write",
      },
      subjectOrgId: "organization-456",
      expectedError: new ClientError(
        "tenancy_mismatch",
        "Member belongs to different organization"
      ),
    },
  ];

  testCases.forEach((tc) =>
    it(tc.name, () => {
      const fn = () =>
        performScopeAuthorizationCheck({
          policy: MOCK_RBAC_POLICY,
          authorizationCheck: tc.authorizationCheck,
          subjectOrgID: tc.subjectOrgId,
          tokenScopes: tc.tokenScopes,
        });

      if (tc.expectedError) {
        expect(fn).toThrow(tc.expectedError);
      } else {
        expect(fn).not.toThrow();
      }
    })
  );
});
