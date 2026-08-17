/**
 * Per-user gateway identity proof.
 *
 * When this app's gateway hits EADDRINUSE it probes the listener already on the
 * port and, historically, sent every configured CCR API key to it after only a
 * JSON-shape check. A process squatting the loopback port (notably one owned by
 * a *different* OS user, who cannot read this user's 0600 config store) could
 * therefore phish those keys.
 *
 * The defense is a challenge-response over a secret stored 0600 in the user's
 * config dir: only a gateway run by the same user can read the secret and answer
 * the challenge, so keys are only ever sent to a listener that proves it.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { CONFIGDIR } from "@ccr/core/config/constants";

export const gatewayIdentityNonceParam = "ccr_identity_nonce";
const identitySecretFile = "gateway-identity.secret";
const isWindows = process.platform === "win32";

let cachedSecret: string | undefined;

function identitySecretPath(): string {
  return path.join(CONFIGDIR, identitySecretFile);
}

/** Read the per-user identity secret, creating a fresh 0600 one on first use. */
export function readOrCreateGatewayIdentitySecret(): string {
  if (cachedSecret) {
    return cachedSecret;
  }
  const file = identitySecretPath();
  try {
    const existing = readFileSync(file, "utf8").trim();
    if (existing) {
      cachedSecret = existing;
      return existing;
    }
  } catch {
    // Not created yet — fall through and write a new one.
  }
  const secret = randomBytes(32).toString("hex");
  try {
    mkdirSync(CONFIGDIR, { recursive: true, mode: 0o700 });
  } catch {
    // Directory may already exist; ignore.
  }
  writeFileSync(file, `${secret}\n`, isWindows ? {} : { mode: 0o600 });
  if (!isWindows) {
    try {
      chmodSync(file, 0o600);
    } catch {
      // Best effort — the file was created with the mode above.
    }
  }
  cachedSecret = secret;
  return secret;
}

/** Read the secret without creating one; returns undefined if none exists locally. */
function readGatewayIdentitySecret(): string | undefined {
  if (cachedSecret) {
    return cachedSecret;
  }
  try {
    const existing = readFileSync(identitySecretPath(), "utf8").trim();
    if (existing) {
      cachedSecret = existing;
      return existing;
    }
  } catch {
    // No secret yet.
  }
  return undefined;
}

export function computeGatewayIdentityProof(secret: string, nonce: string): string {
  return createHmac("sha256", secret).update(nonce).digest("hex");
}

/**
 * Server side: produce a proof for a challenge nonce, or undefined when the nonce
 * is missing/too short. Called by the gateway `/health` handler.
 */
export function gatewayIdentityProofForNonce(nonce: string | undefined | null): string | undefined {
  const trimmed = nonce?.trim();
  if (!trimmed || trimmed.length < 16) {
    return undefined;
  }
  return computeGatewayIdentityProof(readOrCreateGatewayIdentitySecret(), trimmed);
}

/**
 * Client side: verify a proof returned by a probed listener against the local
 * secret. Returns false when no local secret exists (no same-user gateway has
 * ever run) or the proof does not match — i.e. fail closed.
 */
export function verifyGatewayIdentityProof(nonce: string, proof: unknown): boolean {
  if (typeof proof !== "string" || !proof) {
    return false;
  }
  const secret = readGatewayIdentitySecret();
  if (!secret) {
    return false;
  }
  const expected = computeGatewayIdentityProof(secret, nonce);
  const expectedBuffer = Buffer.from(expected, "hex");
  const actualBuffer = Buffer.from(proof, "hex");
  if (expectedBuffer.length === 0 || expectedBuffer.length !== actualBuffer.length) {
    return false;
  }
  return timingSafeEqual(expectedBuffer, actualBuffer);
}

export function createGatewayIdentityNonce(): string {
  return randomBytes(24).toString("hex");
}
