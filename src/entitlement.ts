/**
 * One Durable Object per App Store transaction (keyed by
 * originalTransactionId): the serialization point for the
 * devices-per-transaction cap in relay-protocol.md, "Entitlement proof".
 *
 * Storage layout (SQLite-backed KV):
 *   devices -> { [sha256(deviceToken) hex]: lastSeenAtMs }
 *
 * The object holds hashes of device tokens, never the tokens.  A slot
 * lapses after `RELAY_PRO_DEVICE_SLOT_TTL_S` of silence; every touch
 * prunes lapsed slots first, and an alarm wipes the object once every
 * slot has lapsed, so an abandoned transaction leaves nothing behind.
 */

import { DurableObject } from "cloudflare:workers";

import type { Env } from "./types";

export interface DeviceCapConfig {
  devicesPerTransaction: number;
  slotTtlMs: number;
}

export const DEFAULT_DEVICE_CAP: DeviceCapConfig = {
  devicesPerTransaction: 5,
  slotTtlMs: 5_184_000_000,
};

export type ClaimResult =
  { admitted: true } | { admitted: false; limit: number };

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

/** Pure core of the cap: prune lapsed slots, then admit or refuse. */
export function claimSlot(
  slots: Slots,
  deviceHash: string,
  now: number,
  cfg: DeviceCapConfig,
): { slots: Slots; result: ClaimResult } {
  const live: Slots = {};
  for (const [hash, seenAt] of Object.entries(slots)) {
    if (now - seenAt < cfg.slotTtlMs) live[hash] = seenAt;
  }
  const known = deviceHash in live;
  if (!known && Object.keys(live).length >= cfg.devicesPerTransaction) {
    return {
      slots: live,
      result: { admitted: false, limit: cfg.devicesPerTransaction },
    };
  }
  live[deviceHash] = now;
  return { slots: live, result: { admitted: true } };
}

export class EntitlementState extends DurableObject<Env> {
  /** Hold or refresh `deviceHash`'s slot on this transaction. */
  async claim(deviceHash: string): Promise<ClaimResult> {
    const cfg = deviceCapFromEnv(this.env);
    const now = Date.now();
    const stored = (await this.ctx.storage.get<Slots>("devices")) ?? {};
    const { slots, result } = claimSlot(stored, deviceHash, now, cfg);
    await this.ctx.storage.put("devices", slots);
    await this.ctx.storage.setAlarm(now + cfg.slotTtlMs);
    return result;
  }

  async alarm(): Promise<void> {
    const cfg = deviceCapFromEnv(this.env);
    const now = Date.now();
    const stored = (await this.ctx.storage.get<Slots>("devices")) ?? {};
    const live: Slots = {};
    let newest = 0;
    for (const [hash, seenAt] of Object.entries(stored)) {
      if (now - seenAt < cfg.slotTtlMs) {
        live[hash] = seenAt;
        newest = Math.max(newest, seenAt);
      }
    }
    if (Object.keys(live).length === 0) {
      await this.ctx.storage.deleteAll();
      return;
    }
    await this.ctx.storage.put("devices", live);
    await this.ctx.storage.setAlarm(newest + cfg.slotTtlMs);
  }
}
