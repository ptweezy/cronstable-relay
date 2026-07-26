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
  /** Sealed alert, base64, at most 3000 characters. */
  ciphertext: string;
  /** Opaque coalescing key: 32 lowercase hex characters. */
  collapseId: string;
  /** Maps to the APNs interruption level. */
  priority: "time-sensitive" | "passive";
  /** True for daemon events (the notify: fan-out); routing metadata only. */
  event: boolean;
}

/** What a Durable Object hands back for the worker to turn into HTTP. */
export interface DeliverOutcome {
  status: number;
  body: Record<string, unknown>;
  /** Seconds to advertise in Retry-After on 429 responses. */
  retryAfterS?: number;
}

export interface Env {
  DEVICE: DurableObjectNamespace<
    import("./device").DeviceState & Rpc.DurableObjectBranded
  >;

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

  /** Optional policy tunables (numbers as strings; see policy.ts). */
  RELAY_DEDUP_WINDOW_S?: string;
  RELAY_RATE_CAPACITY?: string;
  RELAY_RATE_REFILL_PER_S?: string;
  RELAY_FLAP_MAX_FORWARDS?: string;
  RELAY_FLAP_WINDOW_S?: string;
  RELAY_COOLDOWN_INTERVAL_S?: string;
  RELAY_FLAP_RESET_S?: string;
}
