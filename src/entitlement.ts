/**
 * One Durable Object per App Store transaction (keyed by
 * originalTransactionId): the serialization point for the
 * devices-per-transaction cap in relay-protocol.md, "Entitlement proof",
 * and the place a revocation of the transaction is remembered.
 *
 * Storage layout (SQLite-backed KV):
 *   devices -> { [sha256(deviceToken) hex]: lastSeenAtMs }
 *   revoked -> RevocationMark   the transaction's refund or revocation
 *
 * The object holds hashes of device tokens, never the tokens.  A slot
 * lapses after `RELAY_PRO_DEVICE_SLOT_TTL_S` of silence; every touch
 * prunes lapsed slots first, and an alarm wipes the object once every
 * slot and the revocation mark have lapsed, so an abandoned transaction
 * leaves nothing behind.
 *
 * A re-post that would change nothing but a slot's refresh time writes
 * nothing: a slot refreshed within `slotRefreshMs` (a day, or a quarter
 * of the TTL when that is shorter) keeps its stored time.
 */

import { DurableObject } from "cloudflare:workers";

import type { Env } from "./types";

const DAY_MS = 86_400_000;

export interface DeviceCapConfig {
  devicesPerTransaction: number;
  slotTtlMs: number;
}

export const DEFAULT_DEVICE_CAP: DeviceCapConfig = {
  devicesPerTransaction: 5,
  slotTtlMs: 5_184_000_000,
};

/**
 * An authentic revocation of the transaction.  A later proof whose
 * purchase it covers and which the App Store signed before it is a
 * replayed pre-refund copy (`revokedBy`).
 */
export interface RevocationMark {
  /** The revoked copy's `signedDate`. */
  signedDate: number;
  /** The revoked transaction's `purchaseDate`; null covers every
   * purchase. */
  purchaseDate: number | null;
  /** Epoch ms at which the mark lapses (the revoked transaction's
   * `expiresDate` plus the grace), or null to keep it. */
  until: number | null;
}

/** The dates of a proof that `claim` checks against the mark. */
export interface ProofDates {
  purchaseDate: number | null;
  signedDate: number;
}

export type ClaimResult =
  /** `slotExpiresAt`: when the device's slot lapses without a re-post. */
  | { admitted: true; slotExpiresAt: number }
  | { admitted: false; limit: number }
  | { admitted: false; revoked: RevocationMark };

type Slots = Record<string, number>;

function num(raw: string | undefined, fallback: number): number {
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function deviceCapFromEnv(env: {
  RELAY_PRO_DEVICES_PER_TRANSACTION?: string;
  RELAY_PRO_DEVICE_SLOT_TTL_S?: string;
}): DeviceCapConfig {
  const d = DEFAULT_DEVICE_CAP;
  return {
    devicesPerTransaction: num(
      env.RELAY_PRO_DEVICES_PER_TRANSACTION,
      d.devicesPerTransaction,
    ),
    slotTtlMs: num(env.RELAY_PRO_DEVICE_SLOT_TTL_S, d.slotTtlMs / 1000) * 1000,
  };
}

/** How recently a slot must have been refreshed for a re-post to leave
 * it as stored. */
export function slotRefreshMs(cfg: DeviceCapConfig): number {
  return Math.min(DAY_MS, cfg.slotTtlMs / 4);
}

/**
 * Pure core of the cap: prune lapsed slots, then admit or refuse.
 * `write` is whether the result differs from what is stored: pruning
 * removed a slot, or the device's slot is new or due a refresh.
 */
export function claimSlot(
  slots: Slots,
  deviceHash: string,
  now: number,
  cfg: DeviceCapConfig,
): { slots: Slots; result: ClaimResult; write: boolean } {
  const live: Slots = {};
  let pruned = false;
  for (const [hash, seenAt] of Object.entries(slots)) {
    if (now - seenAt < cfg.slotTtlMs) live[hash] = seenAt;
    else pruned = true;
  }
  const seenAt = live[deviceHash];
  if (
    seenAt === undefined &&
    Object.keys(live).length >= cfg.devicesPerTransaction
  ) {
    return {
      slots: live,
      result: { admitted: false, limit: cfg.devicesPerTransaction },
      write: pruned,
    };
  }
  if (seenAt !== undefined && now - seenAt < slotRefreshMs(cfg)) {
    return {
      slots: live,
      result: { admitted: true, slotExpiresAt: seenAt + cfg.slotTtlMs },
      write: pruned,
    };
  }
  live[deviceHash] = now;
  return {
    slots: live,
    result: { admitted: true, slotExpiresAt: now + cfg.slotTtlMs },
    write: true,
  };
}

export function markLive(mark: RevocationMark, now: number): boolean {
  return mark.until === null || now < mark.until;
}

/** Whether a live mark refuses a proof: one whose purchase the
 * revocation covers, signed before the revoked copy.  A later renewal,
 * or a copy the App Store signed after the revocation (a reversed
 * refund), passes.  A proof without `purchaseDate` counts as covered. */
export function revokedBy(
  mark: RevocationMark,
  proof: ProofDates,
  now: number,
): boolean {
  if (!markLive(mark, now)) return false;
  const covered =
    (proof.purchaseDate ?? -Infinity) <= (mark.purchaseDate ?? Infinity);
  return covered && proof.signedDate < mark.signedDate;
}

/** Merges two revocations of one transaction into one mark that
 * refuses everything either refuses and lapses with the later one. */
export function mergeMarks(
  stored: RevocationMark | undefined,
  incoming: RevocationMark,
): RevocationMark {
  if (!stored) return incoming;
  const later = (a: number | null, b: number | null) =>
    a === null || b === null ? null : Math.max(a, b);
  return {
    signedDate: Math.max(stored.signedDate, incoming.signedDate),
    purchaseDate: later(stored.purchaseDate, incoming.purchaseDate),
    until: later(stored.until, incoming.until),
  };
}

function sameMark(a: RevocationMark | undefined, b: RevocationMark): boolean {
  return (
    a !== undefined &&
    a.signedDate === b.signedDate &&
    a.purchaseDate === b.purchaseDate &&
    a.until === b.until
  );
}

export class EntitlementState extends DurableObject<Env> {
  /**
   * Hold or refresh `deviceHash`'s slot on this transaction for a proof
   * with `proof`'s dates.  Refuses a proof the revocation mark covers,
   * and a new device once the transaction lifts its maximum.
   */
  async claim(deviceHash: string, proof: ProofDates): Promise<ClaimResult> {
    const cfg = deviceCapFromEnv(this.env);
    const now = Date.now();
    const stored = await this.ctx.storage.get<unknown>(["devices", "revoked"]);
    const mark = stored.get("revoked") as RevocationMark | undefined;
    if (mark && revokedBy(mark, proof, now)) {
      return { admitted: false, revoked: mark };
    }
    const { slots, result, write } = claimSlot(
      (stored.get("devices") as Slots | undefined) ?? {},
      deviceHash,
      now,
      cfg,
    );
    if (write) {
      await this.ctx.storage.put("devices", slots);
      // alarm() re-arms itself from what it finds, so a pending alarm
      // only ever needs lowering: a revocation can leave it at the
      // mark's far `until`, past the slots' lapse.
      const lapse = Math.max(...Object.values(slots)) + cfg.slotTtlMs;
      const alarm = await this.ctx.storage.getAlarm();
      if (alarm === null || alarm > lapse) {
        await this.ctx.storage.setAlarm(lapse);
      }
    }
    return result;
  }

  /**
   * Record an authentic revocation of this transaction by merging it
   * into the stored mark.  A revocation whose merged mark has lapsed
   * changes nothing.  The mark is never cleared early; it lapses with
   * its `until`.
   *
   * A revocation never frees a slot, even the slot of a device whose
   * record it cleared: a live proof from that device can land between
   * the clearing and this call and write the record again on the same
   * slot.  Each slot lapses with its TTL instead, at the `slotExpiresAt`
   * its device's record carries, so no device is on Pro without a live
   * slot and the cap holds under any interleaving.  A device that
   * resubscribes reclaims the slot it still holds.
   */
  async revoke(incoming: RevocationMark): Promise<void> {
    const now = Date.now();
    const existing = await this.ctx.storage.get<RevocationMark>("revoked");
    const mark = mergeMarks(existing, incoming);
    if (!markLive(mark, now) || sameMark(existing, mark)) return;
    await this.ctx.storage.put("revoked", mark);
    if (mark.until !== null) {
      const alarm = await this.ctx.storage.getAlarm();
      if (alarm === null || alarm > mark.until) {
        await this.ctx.storage.setAlarm(mark.until);
      }
    }
  }

  async alarm(): Promise<void> {
    const cfg = deviceCapFromEnv(this.env);
    const now = Date.now();
    const stored = await this.ctx.storage.get<unknown>(["devices", "revoked"]);
    const live: Slots = {};
    let newest = 0;
    let pruned = false;
    for (const [hash, seenAt] of Object.entries(
      (stored.get("devices") as Slots | undefined) ?? {},
    )) {
      if (now - seenAt < cfg.slotTtlMs) {
        live[hash] = seenAt;
        newest = Math.max(newest, seenAt);
      } else {
        pruned = true;
      }
    }
    const mark = stored.get("revoked") as RevocationMark | undefined;
    const keepMark = mark !== undefined && markLive(mark, now);
    const slotCount = Object.keys(live).length;
    if (slotCount === 0 && !keepMark) {
      await this.ctx.storage.deleteAll();
      return;
    }
    if (pruned) {
      if (slotCount === 0) await this.ctx.storage.delete("devices");
      else await this.ctx.storage.put("devices", live);
    }
    if (mark !== undefined && !keepMark) {
      await this.ctx.storage.delete("revoked");
    }
    // Wake when the next thing lapses: the last live slot, or the mark.
    const next = Math.min(
      slotCount > 0 ? newest + cfg.slotTtlMs : Infinity,
      keepMark && mark.until !== null ? mark.until : Infinity,
    );
    if (Number.isFinite(next)) await this.ctx.storage.setAlarm(next);
  }
}
