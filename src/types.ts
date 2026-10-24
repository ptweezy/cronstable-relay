/**
 * Shared types for the relay worker.
 *
 * The wire contract implemented here is cronstable's
 * docs/relay-protocol.md (v1): the daemon POSTs one envelope per
 * (alert, device); the relay owns everything past acceptance.
 */

/** A validated inbound envelope (docs/relay-protocol.md, "Inbound request"). */
export interface Envelope {
  v: 1;
  /** APNs device token, normalized to lowercase hex. */
  device: string;
  /** Sealed alert, base64, at most MAX_CIPHERTEXT_CHARS characters. */
  ciphertext: string;
  /** Opaque coalescing key: 32 lowercase hex characters. */
  collapseId: string;
  /**
   * Optional flap key: 32 lowercase hex characters, the same for every
   * run of one alert.  When present, flap suppression counts forwards
   * per flapId instead of per collapseId; dedup stays on collapseId.
   */
  flapId?: string;
  /** Maps to the APNs interruption level. */
  priority: "time-sensitive" | "passive";
  /** True for daemon events (the notify: fan-out).  Events draw from
   * their own rate bucket, so a flood of job alerts cannot starve an
   * approval gate. */
  event: boolean;
  /**
   * The sealing suite the ciphertext was produced under, forwarded to the
   * app so it knows which key opens it.  Defaulted to "x25519" when the
   * daemon omits it.  Opaque to the relay: an unrecognized value is
   * forwarded, never rejected.
   */
  suite: string;
}

/** What a Durable Object hands back for the worker to turn into HTTP. */
export interface DeliverOutcome {
  status: number;
  body: Record<string, unknown>;
}

/** What DeviceState.status() reports (POST /entitlement's 200 body,
 * before the worker renders instants as ISO strings). */
export interface DeviceStatus {
  plan: "free" | "pro";
  /** Present on "pro": the purchase's expiry in epoch ms (in the past
   * during the grace), or null for no expiry. */
  expiresAt?: number | null;
  /** Present on "pro". */
  environment?: "Production" | "Sandbox";
  /** On "free", this period's forwards that count toward the bound;
   * on "pro", every forward this period. */
  used: number;
  /** The period's bound, or null when unlimited. */
  limit: number | null;
  /** Epoch ms of the next rollover. */
  resetsAt: number;
}

export interface Env {
  DEVICE: DurableObjectNamespace<
    import("./device").DeviceState & Rpc.DurableObjectBranded
  >;
  ENTITLEMENT: DurableObjectNamespace<
    import("./entitlement").EntitlementState & Rpc.DurableObjectBranded
  >;
  /** POST / admission per client address (wrangler.jsonc).  Optional:
   * a relay deployed without the binding skips the check. */
  EDGE_LIMITER?: RateLimit;

  /** Apple push credentials; all set via `wrangler secret put`. */
  APNS_TEAM_ID?: string;
  APNS_KEY_ID?: string;
  /** Contents of the .p8 auth key file (PEM). */
  APNS_AUTH_KEY?: string;

  /** The app bundle id the notification is addressed to. */
  APNS_TOPIC?: string;
  /**
   * Which APNs environment device tokens belong to.  "auto" tries
   * production first and falls back to sandbox when APNs says the token
   * belongs to the other environment, then remembers per device.
   */
  APNS_ENVIRONMENT?: "production" | "sandbox" | "auto";
  /** Seconds one APNs send may take, its retry included (see apns.ts). */
  RELAY_APNS_TIMEOUT_S?: string;

  /** Optional policy tunables (numbers as strings; see policy.ts). */
  RELAY_DEDUP_WINDOW_S?: string;
  RELAY_RATE_CAPACITY?: string;
  RELAY_RATE_REFILL_PER_S?: string;
  RELAY_FLAP_MAX_FORWARDS?: string;
  RELAY_FLAP_WINDOW_S?: string;
  RELAY_COOLDOWN_INTERVAL_S?: string;
  RELAY_FLAP_RESET_S?: string;

  /** Monthly delivery quota (numbers as strings; see quota.ts). */
  RELAY_FREE_MONTHLY_FORWARDS?: string;
  RELAY_DIGEST_INTERVAL_S?: string;
  /** Minimum seconds between burst digests (see quota.ts, BurstState). */
  RELAY_BURST_DIGEST_INTERVAL_S?: string;
  /** Test hook: fixed-length quota periods in seconds instead of months. */
  RELAY_QUOTA_PERIOD_S?: string;

  /** Entitlement proof (see appstore.ts and entitlement.ts). */
  RELAY_PRO_PRODUCT_IDS?: string;
  RELAY_ACCEPT_SANDBOX_ENTITLEMENTS?: string;
  /** Test hook: base64 DER of a root to trust instead of Apple Root CA G3. */
  RELAY_APPLE_ROOT_CERT?: string;
  RELAY_PRO_DEVICES_PER_TRANSACTION?: string;
  RELAY_PRO_DEVICE_SLOT_TTL_S?: string;
  /** Seconds past `expiresDate` a subscription still lifts the quota. */
  RELAY_PRO_GRACE_S?: string;
}
