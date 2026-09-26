# billing-authz — Specification v1.2

> **Amendment 2 (2026-09-26):** makes the specification internally consistent, as found by its
> translation into a Blueprint (Repository Engine 1000, `blueprints/billing-authz.TRANSLATION.md`):
> 29 gaps resolved, including a contradiction that made AT-54, AT-55 and AT-58 impossible to pass
> and AT-31, which could not be written. Five acceptance tests reworded (AT-15, AT-31, AT-32, AT-47,
> AT-56); the count stays 60.

> **Amendment 1 (2026-09-26, AE-D36):** policy zones with a defined matching rule; SCA across the
> EEA plus the UK; the rand (ZAR) as a first-class currency; AT-54…AT-60. The founding version
> (v1.0, SHA-256 `c729147529fe89f3…`) is the one the pipeline ledger witnesses, in this repo's
> first commit; this amendment is recorded in lineage as `CHANGE_MERGED` with its new hash.

> **Frozen 2026-09-26 (Revision 2).** The founding specification of the pipeline repos
> `billing-authz` and `billing-authz-api`. Its SHA-256 (canonical form: UTF-8, LF line endings)
> is recorded in the Repository Engine 1000 pipeline ledger (AE-D28), and this file is `SPEC.md`
> in the first commit of both repos. Amendments go through pull requests; the ledger witnesses
> only this founding version.
>
> **Source:** the founder's *Billing-Auth: System Blueprint* (2026-09-26). **Decisions:** AE-D10
> (pilot targets), AE-D28 (provenance), AE-D30 (pilot subject: billing authorization), AE-D31
> (freeze).

---

## 1. Purpose

**billing-authz** answers one question, deterministically and auditably:

> *Is this billing-related action allowed right now, for this actor, under these conditions?*

It is a **decision layer, not a money-mover**. It sits between product surfaces (checkout, admin
consoles, workers) and the systems that move money (billing core, ledger, payment provider). It
decides and explains; it never charges, refunds, invoices or stores card data.

**Why it exists:** billing rules usually end up scattered through product code (`if plan === "pro"
&& !pastDue && usage < limit`). That's where revenue leaks, disputes get lost and compliance
breaks. billing-authz centralises those rules as versioned policy data, makes every decision
auditable, and lets policy change without a code deploy.

## 2. The two repositories

| Repo | Role | Engine template | Contents |
|---|---|---|---|
| **`billing-authz`** | Core library | `module` | Domain types, the decision engine (evaluator pipeline), policy store, decision log, idempotency, in-memory adapters. **No runtime dependencies.** |
| **`billing-authz-api`** | HTTP service | `module-api` | The HTTP API over the core (`POST /v1/authorize`, batch, health, policies). **Depends on and imports `billing-authz`.** |

Both live in the `billing` system. `billing-authz-api` is the core's first consumer (§8), which is
the pilot's RMM-4 path.

## 3. Scope

### 3.1 In this slice (verifiable from a clean clone, no external services)

- Synchronous authorization of a single request, and batches of up to 100.
- The eight-stage evaluator pipeline (§5) with short-circuit on `DENY`.
- Decisions `ALLOW` · `DENY` · `REQUIRE_VERIFICATION` · `ALLOW_WITH_LIMITS`, with obligations and reasons.
- Policies **as versioned data**, with `effectiveAt`, publish, immutability and rollback (§6).
- **Default-deny:** an action is allowed only if the active policy permits it for that subject (§5.1, stage 3).
- An append-only decision log (§7) and idempotency (§5.4).
- Every external dependency behind a **port** (§4.4), with an **in-memory adapter** shipped.
- An injectable clock: no evaluator reads the system time directly.

### 3.2 Deferred to later phases (blueprint Phases 2–3; ports exist, adapters don't)

Postgres policy/decision storage · Redis entitlement cache · Kafka decision stream · Rego/CEL
policy language · mTLS and per-caller scopes · multi-region active-active · external fraud APIs ·
policy signatures · shadow evaluation and canaries · SDKs · ML scoring · explainability UI ·
**quota reservation and commit** · **resource-ownership checks** (a resource port).

### 3.3 Out of scope (never)

Payment processing · ledger / double-entry accounting · invoice generation · tax calculation ·
**identity / authentication** (billing-authz *consumes* a resolved subject; it never issues or
verifies credentials — that is `billing-auth`'s job, a different repo) · storing card data.

### 3.4 Trust boundary (this slice)

- **Callers are trusted to send the right subject.** billing-authz does not authenticate callers
  (mTLS and scopes are deferred, §3.2).
- **Resource ownership is the caller's responsibility.** This slice does not check that a
  `resource` belongs to the `subject`; for example, an account asking about another account's
  invoice is not detected. The README states this plainly.
- **Verification evidence is trusted as supplied.** `context.verification` (§4.1) is the caller's
  assertion that a step-up or SCA happened; billing-authz checks its age, not its authenticity.

## 4. Public interface — `billing-authz` (core)

All amounts are **integers in minor units** of their ISO-4217 `currency` (cents for USD, yen for
JPY). No floating-point money anywhere. Every money threshold in a policy is a **per-currency map**
(§6); a currency the map does not list is handled **fail-closed**.

### 4.1 Types

```ts
type SubjectType = "account" | "user" | "service" | "admin";
interface SubjectRef { type: SubjectType; id: string }

type Action =
  | "charge" | "refund" | "credit" | "upgrade" | "downgrade" | "cancel"
  | `use_feature:${string}`;

interface ResourceRef { type: "account" | "subscription" | "invoice" | "seat"; id: string }

interface Verification {
  method: "sca" | "step_up";
  reference: string;          // the caller's reference for the completed check
  at: string;                 // ISO-8601, when it completed
}

interface Context {
  amount?: number;            // minor units: an integer, 0 ≤ amount ≤ 10^12
  currency?: string;          // ISO-4217 (three capital letters), required when amount is present
  region?: string;            // ISO-3166 alpha-2 or a zone defined in the policy's `zones` (§6), such as "EU"
  quantity?: number;          // metered units requested (quota): an integer ≥ 0
  plan?: string;              // target plan: required for upgrade and downgrade
  verification?: Verification;
  ip?: string;
  riskHints?: Record<string, string | number | boolean>;
}

interface AuthorizeRequest {
  subject: SubjectRef;
  action: Action;
  resource?: ResourceRef;
  context?: Context;
  idempotencyKey?: string;
}

type DecisionKind = "ALLOW" | "DENY" | "REQUIRE_VERIFICATION" | "ALLOW_WITH_LIMITS";

type Obligation =
  | { type: "max_amount"; value: number }          // minor units of the request's currency
  | { type: "require_sca"; value: true }
  | { type: "quota_warning"; value: { used: number; limit: number } }
  | { type: "overage_billable"; value: { units: number } }
  | { type: "risk_unchecked"; value: true }
  | { type: "grace_until"; value: string };        // ISO-8601

interface Reason { code: string; stage: StageName; message: string; details?: Record<string, unknown> }

interface Decision {
  decisionId: string;        // UUID v4, from an injectable id source (Amendment 2)
  decision: DecisionKind;
  obligations: Obligation[];
  reasons: Reason[];
  policyVersion: string;
  ttlSeconds: number;
  evaluatedAt: string;       // ISO-8601, from the injected clock
  expiresAt: string;         // evaluatedAt + ttlSeconds; a caller must not act on a decision after this
  replay?: true;             // present when returned from the idempotency store (§5.4)
}
```

### 4.2 Engine

```ts
interface EngineDeps {
  clock: Clock;
  subjects: SubjectSource;
  entitlements: EntitlementSource;
  quotas: QuotaSource;
  payments: PaymentHealthSource;
  risk: RiskSource;
  policies: PolicyStore;
  log: DecisionLog;
  idempotency?: IdempotencyStore;   // defaults to in-memory
}

function createEngine(deps: EngineDeps): {
  authorize(req: AuthorizeRequest): Promise<Decision>;
  authorizeBatch(reqs: AuthorizeRequest[]): Promise<Decision[]>;   // ≤ 100, results in order
};
```

Invalid requests throw `AuthzError` with a stable `code` (§9). Validation (§5.6) happens before
any stage runs.

### 4.3 Stage names

`identity` · `hard_blocks` · `permission` · `quota` · `payment_health` · `risk` · `compliance` · `obligations`

(`permission` is the blueprint's "entitlement check", widened: *may this subject perform this
action?* — plans and entitlements for customers, roles for operators.)

### 4.4 Ports (interfaces) and shipped adapters

| Port | Question it answers | In-memory adapter |
|---|---|---|
| `Clock` | What time is it? | `fixedClock(iso)`, `systemClock()` |
| `SubjectSource` | Who is this subject: status, home region, roles, flags, current plan? | `InMemorySubjects` |
| `EntitlementSource` | Which features does the subject hold, valid when, with which limits? | `InMemoryEntitlements` |
| `QuotaSource` | Current usage, limit and mode (`soft` / `hard` / `overage`) per quota. **Read-only.** | `InMemoryQuotas` |
| `PaymentHealthSource` | Subscription/payment state: active, past_due, and the grace deadline | `InMemoryPaymentHealth` |
| `RiskSource` | Risk score 0–100 for a request (may time out) | `StaticRisk` |
| `PolicyStore` | Versioned policy data (§6) | `InMemoryPolicyStore` |
| `DecisionLog` | Append-only record of decisions (§7) | `InMemoryDecisionLog` |
| `IdempotencyStore` | Decisions by idempotency key | `InMemoryIdempotencyStore` |

**Records the ports return (Amendment 2):**
- **Subject:** `{ type, status: "active" | "suspended" | "closed", homeRegion?, roles: string[], flags: ("fraud" | "legal_hold")[], plan? }`.
  A `user`'s entitlements, plan and payment state are its **own** records (no account inheritance in this slice).
- **Entitlement:** `{ feature, validFrom?, validUntil? }`, valid at *now* when `validFrom ≤ now < validUntil`; a missing bound is open.
- **Quota:** `{ key, used, limit, mode }`. A request's quota is the one keyed by the **feature** of `use_feature:<key>`.
- **PaymentHealth:** `{ state: "active" | "past_due", graceUntil? }`.

## 5. Decision semantics

### 5.1 Pipeline

Stages run in the order of §4.3. Each returns `pass`, `deny`, `verify`, or `limit` (with obligations),
plus reasons. **Within a stage, rules are evaluated in the order written below; the first `deny` is
the one reported** (Amendment 2). **A `deny` stops the pipeline immediately**: later stages, including external
calls, do not run.

**Regions:** a region is **blocked** if either the request's `context.region` or the subject's home
region matches an entry in `blockedRegions`. Where a rule needs *the* region (SCA), it uses
`context.region`, falling back to the subject's home region.

**Matching (Amendment 1):** a region *matches* a listed entry when
1. they are equal; or
2. the entry is a zone (a key of `zones`, §6) that contains the region; or
3. the region is itself a zone and **every** member of it matches the entry by rule 1 or 2
   (so `"EU"` matches `"EEA"`, because every EU member is in the EEA).

Zones contain only ISO-3166 alpha-2 codes; they do not nest. The rule applies to
`blockedRegions` and `sca.regions`, for both the request's region and the subject's home region.

| # | Stage | Rules in this slice (thresholds come from the active policy, §6) |
|---|---|---|
| 1 | `identity` | Unknown subject → `deny` `unknown_subject`. Status `suspended` / `closed` → `deny` `subject_suspended` / `subject_closed`. |
| 2 | `hard_blocks` | Subject flag `fraud` or `legal_hold` → `deny` `fraud_hold` / `legal_hold`. A blocked region → `deny` `region_blocked`. |
| 3 | `permission` | **Default-deny:** the action must be listed in `permissions` for the subject's type (and, for `admin` and `user`, one of its roles **when the permission lists roles**); otherwise `deny` `not_permitted`. **Operator thresholds:** `refund` and `credit` whose `amount` exceeds `operator.financeThreshold[currency]` require role `finance`; an unlisted currency always requires it; otherwise `deny` `role_required`. **Features:** `use_feature:<key>` also needs an entitlement for `<key>` valid at *now*; otherwise `deny` `not_entitled`. **Plans:** `upgrade` / `downgrade` need `context.plan` to appear in `plans[currentPlan].upgradeTo` / `downgradeTo`; otherwise `deny` `plan_not_permitted`. The current plan is the subject's, or **for an `admin`, that of the `resource` account** (Amendment 2). |
| 4 | `quota` | If `quantity` is present, per the quota's mode, where *above the limit* means `used + quantity > limit`: `hard` → `deny` `quota_exceeded`; `soft` → `limit` `quota_warning`; `overage` → `limit` `overage_billable` with `units = used + quantity − limit`. |
| 5 | `payment_health` | Applies to **premium actions** only: the policy's `premiumActions` (default `upgrade` and every `use_feature:*`). **Never `charge`**: collecting from a past-due account (dunning) must stay possible. Payment state `past_due` beyond grace (`now > graceUntil`) → `deny` `past_due` with `details.grace_until`. Within grace (`now ≤ graceUntil`) → `limit` `grace_until`. |
| 6 | `risk` | Applies to actions with an `amount`. Score ≥ `risk.denyAt` (default 80) → `deny` `risk_high`. Score ≥ `risk.verifyAt` (default 50) → `verify` `risk_elevated`, **unless** `context.verification` completed within `risk.verificationMaxAgeSeconds` (default 600) and not later than *now* (a future timestamp is not accepted), in which case `pass` with reason `verified`. **Timeout** (no score within `risk.timeoutMs`, default 250): if `amount ≥ risk.highValueAmount[currency]`, or the currency is unlisted → `deny` `risk_unavailable` (fail-closed); otherwise `limit` `risk_unchecked` (fail-open). |
| 7 | `compliance` | `charge` with `amount > 0` whose region matches an entry in `sca.regions` (default `["EEA", "GB"]`) → `limit` `require_sca`. |
| 8 | `obligations` | Composes obligations (§5.3). **Plan limits** (only when `context.amount` is present): a plan carrying `limits.maxAmount[currency]` attaches `max_amount`; if the plan sets a `maxAmount` but not for the request's currency → `deny` `currency_not_supported`. *(Entitlement-level limits were removed by Amendment 2: nothing defined which entitlement governs a charge.)* |

### 5.2 Final decision

`DENY` if any stage denied · else `REQUIRE_VERIFICATION` if any stage returned `verify` · else
`ALLOW_WITH_LIMITS` if any obligation exists · else `ALLOW`. A `DENY` carries **no** obligations; a
`REQUIRE_VERIFICATION` carries those collected before and after the `verify` (Amendment 2).

### 5.3 Obligation composition

`max_amount`: the **minimum** of all values · `require_sca`: present if any stage requires it ·
`quota_warning` / `overage_billable` / `grace_until`: at most one each, the most restrictive
(highest `used / limit`; most `units`; earliest date) ·
obligations are deterministically ordered by `type`.

### 5.4 Idempotency

When `idempotencyKey` is present, the engine stores the decision under the key for
`idempotency.windowSeconds` (default 86 400). **The same key with the same inputs** returns the
**same** decision (same `decisionId`, same `evaluatedAt` and `expiresAt`) marked `replay: true`,
without re-evaluating. A replay can therefore be **expired**; the caller must check `expiresAt` and
use a new key to get a fresh decision. **The same key with different inputs** throws
`AuthzError("IDEMPOTENCY_CONFLICT")`. Inputs are compared by `inputsHash` (§7).

### 5.5 TTL

`ttlSeconds` is `ttl.default` (default **300**, as in the blueprint's example response), unless the
policy sets `ttl.byAction[action]`. `expiresAt = evaluatedAt + ttlSeconds`.

### 5.6 Validation (before any stage runs)

`INVALID_REQUEST` when: the subject id is empty or the type unknown · the action is unknown ·
`amount` is not an integer in `0…10^12` · `amount` is present without a valid three-letter
`currency` · `quantity` is not a non-negative integer · `upgrade` / `downgrade` lacks `plan` ·
`verification.at` is not a valid ISO-8601 time · `quantity` on an action other than `use_feature:<key>` ·
an `admin`'s `upgrade` / `downgrade` without a `resource` of type `account`. **Nothing is evaluated
or logged** for an invalid request.

### 5.7 Side effects

`authorize` is **read-only** except for two writes: the decision log (§7) and the idempotency
store. It never reserves or consumes quota, changes a subject, or calls a money-moving system.
Quota reservation and commit are deferred (§3.2).

## 6. Policy model

A **policy version** is data: `{ version, effectiveAt, rules }`.

```ts
type CurrencyMap = Record<string /* ISO-4217 */, number /* minor units */>;
type ActionKey = Action | "use_feature:*";

interface PolicyRules {
  permissions: Partial<Record<ActionKey, { subjectTypes: SubjectType[]; roles?: string[] }>>;
  operator: { financeThreshold: CurrencyMap };
  plans: Record<string, { upgradeTo: string[]; downgradeTo: string[]; limits?: { maxAmount?: CurrencyMap } }>;
  blockedRegions: string[];
  premiumActions: ActionKey[];
  risk: { denyAt: number; verifyAt: number; highValueAmount: CurrencyMap; verificationMaxAgeSeconds: number; timeoutMs: number };
  sca: { regions: string[] };
  zones: Record<string, string[]>;   // zone name → ISO-3166 alpha-2 members (zones do not nest)
  ttl: { default: number; byAction?: Partial<Record<ActionKey, number>> };
  idempotency: { windowSeconds: number };
}
```

**Defaults** (the shipped example policy, and the fixtures for §11):

| Rule | Default |
|---|---|
| `permissions` | `charge`: account, service · `refund`, `credit`: admin with role `support_agent` or `finance` · `upgrade`, `downgrade`, `cancel`: account; admin with `support_agent` or `finance` · `use_feature:*`: account, user |
| `operator.financeThreshold` | `{ USD: 2500, EUR: 2500, GBP: 2500, JPY: 3500, ZAR: 45000 }` ($25 and equivalents; R 450) |
| `risk` | `denyAt 80` · `verifyAt 50` · `highValueAmount { USD: 10000, EUR: 10000, GBP: 10000, JPY: 15000, ZAR: 180000 }` ($100 and equivalents; R 1 800) · `verificationMaxAgeSeconds 600` · `timeoutMs 250` |
| `premiumActions` | `upgrade`, `use_feature:*` |
| `sca.regions` | `["EEA", "GB"]` (PSD2 across the EEA, plus the UK) |
| `zones` | `EU`: AT, BE, BG, HR, CY, CZ, DK, EE, FI, FR, DE, GR, HU, IE, IT, LV, LT, LU, MT, NL, PL, PT, RO, SK, SI, ES, SE · `EEA`: the EU members plus IS, LI, NO |
| `blockedRegions` | `[]` |
| `plans` | `{}` (deployments and the tests publish their own) |
| `ttl.default` | 300 |
| `idempotency.windowSeconds` | 86 400 |

Like every threshold, the ZAR amounts are policy data, reviewed periodically as exchange rates drift.

- `publish(version)` makes a version **immutable**: its content hash is recorded, and publishing
  the same version identifier with different content fails `POLICY_IMMUTABLE`.
- The store keeps an **activation history**: `publish(v)` adds an activation at `v.effectiveAt`;
  `rollback(toVersion)` adds one at *now*. **The active version is the one named by the latest
  activation at or before now** (Amendment 2; this reconciles publish and rollback).
- Rollback is recorded, not destructive: no version is ever deleted.
- Every decision records the `policyVersion` it was evaluated under.
- **No evaluation without a policy:** if no version is active, `authorize` throws `NO_ACTIVE_POLICY`.

## 7. Decision log contract

Every decision (including batch items and idempotent replays marked `replay: true`) is appended as:

```ts
interface DecisionRecord {
  decisionId: string; at: string;
  subject: SubjectRef; action: Action; resource?: ResourceRef;
  inputsHash: string;         // SHA-256 of the canonical JSON (keys sorted at every level, no whitespace,
                              // undefined omitted) of the request, excluding idempotencyKey
  policyVersion: string;
  decision: DecisionKind; obligations: Obligation[]; reasonCodes: string[];
  latencyMs: number;          // a monotonic timer, never the injected clock
  replay?: true;
}
```

- **Append-only:** the `DecisionLog` port has `append` and read operations only. There is no update or delete.
- **PII minimisation:** raw `context` (amounts, IPs, risk hints, verification references) is **not** stored; only `inputsHash`.
- The log is written **before** the idempotency store. A log failure makes `authorize` throw
  `DECISION_LOG_UNAVAILABLE` and nothing is stored. **No unlogged decisions.**

## 8. Consumers

| Consumer | How | Status |
|---|---|---|
| **`billing-authz-api`** | Declares `billing-authz` as a dependency and imports it | **Pilot.** This is the core's RMM-4 path (AE-D10 target 4) |
| Future callers: `billing-worker`, `payment-gateway`, checkout, admin console | HTTP contract (§10) | Not pilot evidence: today they're template copies (RMM-1), and RMM-4 only counts consumers at RMM-3+ |
| `billing-auth` (authentication) | Could supply a verified subject through `SubjectSource` in a later phase | Not a dependency |

## 9. Errors

`AuthzError` codes: `INVALID_REQUEST` (400) · `BATCH_TOO_LARGE` (413) · `IDEMPOTENCY_CONFLICT` (409)
· `NO_ACTIVE_POLICY` (503) · `POLICY_IMMUTABLE` (409) · `DECISION_LOG_UNAVAILABLE` (503).
HTTP bodies: `{ "error": { "code": "...", "message": "...", "details": { ... } } }`.

**Batches** read the clock **once**: every item shares that `evaluatedAt`. They are validated as a whole before anything runs: if any item is invalid, or two items
share an `idempotencyKey`, the whole batch fails `INVALID_REQUEST` (with the offending indexes in
`details`), and **nothing is evaluated or logged**.

## 10. Public interface — `billing-authz-api` (service)

| Method | Path | Body → Response |
|---|---|---|
| `POST` | `/v1/authorize` | `AuthorizeRequest` (JSON, snake_case on the wire) → `Decision` |
| `POST` | `/v1/authorize/batch` | `{ "requests": AuthorizeRequest[] }` (≤ 100) → `{ "decisions": Decision[] }` |
| `GET` | `/v1/policies/active` | → `{ "version", "effective_at" }` |
| `GET` | `/health` | → `{ "status": "ok" }` (the engine's smoke test) |

Wire format follows the blueprint (`idempotency_key`, `policy_version`, `decision_id`,
`ttl_seconds`, plus `expires_at`). Configuration from environment variables (`PORT`, default 3000;
`HOST`, default `localhost`; `POLICY_FILE`); **no secret has a default value**. On start the service
logs `billing-authz-api running on port <PORT>` (the engine's API smoke test waits for "running on
port"). Caller authentication and resource ownership are out of this slice (§3.4), and the README
says so plainly.

**Deployment target:** *to be decided by the founder* (Amendment 2, G-29); a "working system"
cannot be claimed without it. **Availability:** not measured in this slice (G-28).

## 11. Acceptance tests

Each test's name starts with its ID (`AT-01 …`), so evidence can be traced to this list. All run
from a clean clone with in-memory adapters, the fixed clock `2026-09-26T12:00:00Z`, and the default
policy of §6 published as version `2026-09-01` (effective `2026-09-01T00:00:00Z`) with two plans:
`starter` (`upgradeTo: ["pro"]`, `limits.maxAmount: { USD: 5000, EUR: 5000, GBP: 5000, ZAR: 90000 }`)
and `pro` (`downgradeTo: ["starter"]`). Unless stated otherwise, the account `acct_123` is active, in
region `EU`, on `starter`, with payment state `active` and an entitlement to `advanced_export`; risk is
low (score 10). The other subjects are `user_1`, `svc_billing` (service), `admin_support` (role
`support_agent`) and `admin_finance` (role `finance`), all active (Amendment 2).

**Core (`billing-authz`)**

| ID | Given / When | Then |
|---|---|---|
| AT-01 | Entitled account; `use_feature:advanced_export` | `ALLOW`, no obligations (blueprint 6.1) |
| AT-02 | Account without that entitlement | `DENY` · `not_entitled` · stage `permission` |
| AT-03 | Entitlement that expired before *now* | `DENY` · `not_entitled` |
| AT-04 | `charge` 4 900 USD on `inv_456` | `ALLOW_WITH_LIMITS` with `max_amount` 5 000 and `require_sca` (blueprint 4.1 / 6.2) |
| AT-05 | `refund` 4 900 USD by admin role `support_agent` | `DENY` · `role_required` at `permission`; **the risk source is not called** (spy) (blueprint 6.3) |
| AT-06 | `refund` 4 900 USD by admin role `finance` | `ALLOW` |
| AT-07 | `refund` 2 000 USD by `support_agent` (below the threshold) | `ALLOW` |
| AT-08 | `refund` 3 000 **JPY** by `support_agent` (below the JPY threshold of 3 500) | `ALLOW`, while the same number in USD would be denied |
| AT-09 | `refund` 1 000 **CHF** (no threshold for CHF) by `support_agent` | `DENY` · `role_required` (fail-closed) |
| AT-10 | An account attempts `refund`; a service attempts `cancel` | `DENY` · `not_permitted` for both (default-deny) |
| AT-11 | `upgrade` to a plan listed in `upgradeTo` | `ALLOW` |
| AT-12 | `upgrade` to a plan not listed | `DENY` · `plan_not_permitted` |
| AT-13 | Account `past_due`, grace ended; `upgrade` | `DENY` · `past_due` with `details.grace_until` (blueprint 6.4) |
| AT-14 | Account `past_due`, within grace; `upgrade` | `ALLOW_WITH_LIMITS` with `grace_until` |
| AT-15 | Account `past_due`, grace ended; **the account itself** makes a `charge` (dunning must stay possible) | **not** denied by `payment_health`: the decision comes from the later stages |
| AT-16 | Unknown subject | `DENY` · `unknown_subject` |
| AT-17 | Suspended subject; closed subject | `DENY` · `subject_suspended`; `DENY` · `subject_closed` |
| AT-18 | Subject flagged `fraud` | `DENY` · `fraud_hold` at `hard_blocks`; **no later stage is called** (spies) |
| AT-19 | Subject flagged `legal_hold` | `DENY` · `legal_hold` |
| AT-20 | Blocked region in `context.region`; blocked home region with no `context.region` | `DENY` · `region_blocked` for both |
| AT-21 | `quantity` above a `hard` quota | `DENY` · `quota_exceeded` |
| AT-22 | `quantity` above a `soft` quota | `ALLOW_WITH_LIMITS` · `quota_warning` |
| AT-23 | `quantity` 120 against an `overage` quota of 100 | `ALLOW_WITH_LIMITS` · `overage_billable` with `units` 20 |
| AT-24 | Risk score 85 | `DENY` · `risk_high` |
| AT-25 | Risk score 60, no verification | `REQUIRE_VERIFICATION` · `risk_elevated` |
| AT-26 | Risk score 60 with verification 5 minutes old; then 20 minutes old | the first is not `REQUIRE_VERIFICATION` (reason `verified`); the second is |
| AT-27 | Risk source times out; `charge` 20 000 USD | `DENY` · `risk_unavailable` (fail-closed) |
| AT-28 | Risk source times out; `charge` 1 000 USD | `ALLOW_WITH_LIMITS` · `risk_unchecked` (fail-open) |
| AT-29 | Risk source times out; amount in a currency with no `highValueAmount` | `DENY` · `risk_unavailable` (fail-closed) |
| AT-30 | `charge` in region `US`; `charge` with no `context.region` by an account whose home region is `EU` | no `require_sca`; `require_sca` |
| AT-31 | *(component test of §5.3)* obligations `max_amount` 5 000 and 3 000 are composed | one `max_amount` = 3 000 |
| AT-32 | `charge` 4 900 **CHF** (a currency the plan's `maxAmount` does not list) | `DENY` · `currency_not_supported` |
| AT-33 | Same `idempotencyKey`, same inputs, twice | identical `decisionId`, `evaluatedAt` and `expiresAt`; second response `replay: true`; second log record `replay` |
| AT-34 | The same replay after the original's `expiresAt` | returned unchanged, with `expiresAt` in the past (detectably expired) |
| AT-35 | Same `idempotencyKey`, different amount | `IDEMPOTENCY_CONFLICT` |
| AT-36 | Negative amount; fractional amount; amount without currency; currency `usd`; `upgrade` without `plan` | `INVALID_REQUEST` for each; **nothing logged** |
| AT-37 | Every decision in AT-01…AT-35 | exactly one log record each, with the correct `policyVersion` and `inputsHash`; **no raw `context` in the log** |
| AT-38 | Publish policy v2 with a later `effectiveAt`; clock before / after | v1 before, v2 after; decisions record the version used |
| AT-39 | Re-publish v1 with different content | `POLICY_IMMUTABLE` |
| AT-40 | Roll back from v2 to v1 | v1 active again; v2 still retrievable |
| AT-41 | No active policy | `NO_ACTIVE_POLICY` |
| AT-42 | Decision log throws on append | `DECISION_LOG_UNAVAILABLE`; no decision returned; **nothing in the idempotency store** |
| AT-43 | Batch of 3 mixed requests; batch of 101; batch with one invalid item; batch with a repeated `idempotencyKey` | 3 decisions in order; `BATCH_TOO_LARGE`; `INVALID_REQUEST` with nothing evaluated or logged; `INVALID_REQUEST` |
| AT-44 | 100 decisions of every kind | quota usage, subjects, entitlements and payment state are **unchanged** (read-only, §5.7) |
| AT-45 | 10 000 decisions with in-memory adapters | p99 latency < 25 ms (blueprint cached-path target) |
| AT-46 | The same request evaluated twice with the same fixed clock and policy | identical decision apart from `decisionId`: **deterministic** |

**Service (`billing-authz-api`)**

| ID | Given / When | Then |
|---|---|---|
| AT-47 | `POST /v1/authorize` with `{ "subject": { "type": "account", "id": "acct_123" }, "action": "charge", "resource": { "type": "invoice", "id": "inv_456" }, "context": { "amount": 4900, "currency": "USD" } }` (the blueprint's example request) | 200 and the blueprint's example response: `decision` `ALLOW_WITH_LIMITS`, `obligations` `[max_amount 5000, require_sca true]`, `policy_version` `2026-09-01`, `ttl_seconds` 300, plus `decision_id` and `expires_at` |
| AT-48 | `GET /health` | 200 `{ "status": "ok" }` |
| AT-49 | Malformed body | 400 `INVALID_REQUEST` |
| AT-50 | Idempotency conflict over HTTP | 409 `IDEMPOTENCY_CONFLICT` |
| AT-51 | Batch of 101; batch with one invalid item | 413 `BATCH_TOO_LARGE`; 400 `INVALID_REQUEST` |
| AT-52 | `GET /v1/policies/active` | 200 `{ "version": "2026-09-01", "effective_at": … }` |
| AT-53 | The service's decisions come from `billing-authz` (imported, not reimplemented) | a spy on the core's `authorize` is called by the handler |

**Amendment 1** (core, `billing-authz`):

| ID | Given / When | Then |
|---|---|---|
| AT-54 | `charge` 4 900 EUR with `context.region` `"DE"` | `require_sca` (DE ∈ EEA) |
| AT-55 | `charge` 4 900 GBP with `context.region` `"GB"` | `require_sca` |
| AT-56 | `charge` 1 000 USD with `context.region` `"IS"` (EEA, not EU) | `require_sca`; and `"US"` → none |
| AT-57 | `refund` 40 000 ZAR by `support_agent`; then 50 000 ZAR | `ALLOW`; then `DENY` · `role_required` |
| AT-58 | Risk source times out; `charge` 150 000 ZAR; then 200 000 ZAR | `ALLOW_WITH_LIMITS` · `risk_unchecked`; then `DENY` · `risk_unavailable` |
| AT-59 | Policy zone `SANCTIONED = ["KP"]`, `blockedRegions` `["SANCTIONED"]`; request from `"KP"`; subject whose home region is `"KP"` | `DENY` · `region_blocked` for both |
| AT-60 | A subject with home region `"FR"`, no `context.region`; `charge` > 0 | `require_sca` (home-region fallback through the zone) |

AT-04, AT-30 and AT-47 keep their meaning under the new default: the fixture account's region
`"EU"` is a zone, and every EU member is in the EEA (matching rule 3).

## 12. RMM evidence plan

Provenance for both repos: **`pipeline`**, witnessed by one ledger entry each, recorded **before**
the repo exists, with this file's SHA-256, and this file in each repo's **first commit** (AE-D28).
Implementation arrives through pull requests the founder merges (AE-D12).

| Level | Criterion (RMM v2) | How this spec satisfies it | Evidence the engine collects |
|---|---|---|---|
| RMM-1 | integrity · clean install · build · smoke | Engine-scaffolded repos with `system.json`; `npm ci` + `npm run build`; core: `node dist/index.js` exits 0; service: `/health` 200 | `verify-assets`; `promote` deep run |
| RMM-2 | own tests pass · CI green on the current commit · CI builds **and** tests | AT-01…AT-60 under `npm test`; template CI (install, build, test, smoke) | deep run; `actions/workflows/ci.yml` runs |
| RMM-3 | direct evidence · N ≥ 0.5 · ≥ 150 original lines · original passing tests · README says what it does | Original engine, policy store, log and HTTP layer. Expected core ≫ 150 lines. README from §1–§3 with install and usage, and §3.4 | `engine promote` (Novelty vs template, siblings **and reference assets**, AE-D28) |
| RMM-4 | consumed by an RMM-3+ repo | **Core:** `billing-authz-api` depends on and imports it (AT-53). **Service:** no consumer in the pilot | `promote` consumer check (dependency + import) |
| RMM-5 | P = 1.0 + release/package/deployment | MIT LICENSE · no default secrets · `npm audit` clean · README install+usage · `engines.node ≥ 20` · GitHub release `v0.1.0` | `promote` readiness checks |

**Pilot targets this plan serves (AE-D10, pipeline only):** both repos at **RMM-3**, the core at
**RMM-4**. A third pilot repo (for example an SDK or a real `billing-worker` consumer) would be a
separate specification and ledger entry.

## 13. Definition of done (this slice)

1. Both repos exist, created after their ledger entries, with this `SPEC.md` in their first commit.
2. All 60 acceptance tests (53 founding + 7 from Amendment 1) pass locally and in CI; CI builds and tests.
3. `engine promote billing-authz-api`, then `engine promote billing-authz`: the service at RMM-3+, the core at RMM-4+, provenance `pipeline` for both.
4. `engine scorecard` shows **Pipeline Asset Count ≥ 2**.
