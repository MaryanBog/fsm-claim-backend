// index.js — FSM claim backend (fixed v2)
// Node 18+
//
// Endpoints:
//   GET  /health      -> { ok: true }
//   POST /challenge   -> { message, nonce, expiresAt, weekId }
//   POST /claim       -> { txBase64, weekId }
//   POST /confirm     -> { ok: true, weekId }
//
// Env:
//   RPC_URL=...
//   FSM_MINT=...
//   FSM_DECIMALS=6
//   FSM_AMOUNT=1
//   DISTRIBUTOR_SECRET_KEY=[...]
//   ALLOWED_ORIGIN=... (optional)
//   PORT=3000

import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { Buffer } from "buffer";
import { PublicKey, Connection, Keypair, Transaction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferInstruction,
} from "@solana/spl-token";

const app = express();
app.use(express.json({ limit: "1mb" }));

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
app.use(
  cors({
    origin: ALLOWED_ORIGIN === "*" ? true : ALLOWED_ORIGIN,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

const RPC_URL = mustEnv("RPC_URL");
const FSM_MINT = new PublicKey(mustEnv("FSM_MINT"));
const FSM_DECIMALS = Number(process.env.FSM_DECIMALS ?? "6");
const FSM_AMOUNT_HUMAN = String(process.env.FSM_AMOUNT ?? "1"); // keep as string
const distributorSecret = JSON.parse(mustEnv("DISTRIBUTOR_SECRET_KEY"));
const DISTRIBUTOR = Keypair.fromSecretKey(Uint8Array.from(distributorSecret));

const connection = new Connection(RPC_URL, "confirmed");

// Store claims locally (weekly reset).
// NOTE: On Render Free this filesystem may reset on redeploy/restart.
// Weekly reset is handled logically by weekId.
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.cwd();
const CLAIMS_FILE = path.join(DATA_DIR, "claims.json");

// --- config ---
const CHALLENGE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const PENDING_TTL_MS = 20 * 60 * 1000; // 20 minutes

function currentWeekIdUTC() {
  // Week counter within year (simple, deterministic; good enough for weekly reset)
  const d = new Date();
  const year = d.getUTCFullYear();
  const start = new Date(Date.UTC(year, 0, 1));
  const day = Math.floor((d - start) / 86400000) + 1;
  const week = Math.ceil(day / 7);
  return `${year}-W${String(week).padStart(2, "0")}`;
}

function loadDb() {
  const weekId = currentWeekIdUTC();
  try {
    const db = JSON.parse(fs.readFileSync(CLAIMS_FILE, "utf8"));
    if (!db.weekId || db.weekId !== weekId) {
      return { weekId, claimed: {}, pending: {}, challenges: {} };
    }
    return {
      weekId,
      claimed: db.claimed || {},
      pending: db.pending || {},
      challenges: db.challenges || {},
    };
  } catch {
    return { weekId, claimed: {}, pending: {}, challenges: {} };
  }
}

function saveDb(db) {
  fs.writeFileSync(CLAIMS_FILE, JSON.stringify(db, null, 2));
}

function nowMs() {
  return Date.now();
}

function cleanupDb(db) {
  const t = nowMs();

  // expire challenges
  for (const [wallet, ch] of Object.entries(db.challenges || {})) {
    if (!ch?.expiresAt || t > ch.expiresAt) delete db.challenges[wallet];
  }
  // expire pending
  for (const [wallet, p] of Object.entries(db.pending || {})) {
    if (!p?.expiresAt || t > p.expiresAt) delete db.pending[wallet];
  }
}

// Message user signs (no SOL, just signature)
function buildClaimMessage(userPubkey, nonce, weekId, expiresAt) {
  return [
    "Flexion Support Mark (FSM) — Claim",
    "I am claiming FSM as a symbolic on-chain support badge.",
    `Wallet: ${userPubkey}`,
    `Week: ${weekId}`,
    `Nonce: ${nonce}`,
    `ExpiresAt: ${new Date(expiresAt).toISOString()}`,
    "No sale. No exchange. No expectations of profit.",
  ].join("\n");
}

async function getLatestBlockhashWithRetry(max = 5) {
  let lastErr;
  for (let i = 0; i < max; i++) {
    try {
      return await connection.getLatestBlockhash("confirmed");
    } catch (e) {
      lastErr = e;
      const msg = String(e?.message || e);
      if (!msg.includes("429")) throw e;
      await new Promise(r => setTimeout(r, 400 * (i + 1)));
    }
  }
  throw lastErr;
}

/**
 * NOTE: name kept as-is ("Bs58") to avoid touching call-sites.
 * Actual expected encoding for `signature` here is BASE64 (from the frontend).
 */
function verifySignatureBs58({ userPubkey, message, signature }) {
  const pubkey = new PublicKey(userPubkey);
  const msgBytes = new TextEncoder().encode(message);

  // base64 -> Uint8Array
  const sigBuf = Buffer.from(String(signature), "base64");
  if (sigBuf.length !== 64) return false; // ed25519 signature must be 64 bytes

  return nacl.sign.detached.verify(msgBytes, new Uint8Array(sigBuf), pubkey.toBytes());
}

function parseHumanAmountToU64BigInt(humanStr, decimals) {
  // Safe decimal parsing without float
  // "1" with decimals=6 -> 1000000n
  const s = String(humanStr).trim();
  if (!s || s.startsWith("-")) throw new Error("Invalid amount");
  const [iRaw, fRaw = ""] = s.split(".");
  const i = iRaw.replace(/^0+(?=\d)/, "");
  const f = fRaw.replace(/[^0-9]/g, "");
  if (!/^\d+$/.test(i || "0")) throw new Error("Invalid amount");

  const fPadded = (f + "0".repeat(decimals)).slice(0, decimals);
  const full = (i || "0") + fPadded;
  const v = BigInt(full || "0");
  if (v <= 0n) throw new Error("Invalid amount");
  return v;
}

// Validate that txSig is a transfer of FSM from distributor ATA to user's ATA for expected amount
async function validateTransferTx({ txSig, userWallet }) {
  const parsed = await connection.getParsedTransaction(txSig, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });

  if (!parsed) return { ok: false, reason: "Transaction not found" };
  if (parsed.meta?.err) return { ok: false, reason: "Transaction failed" };

  const userPk = new PublicKey(userWallet);
  const userAta = getAssociatedTokenAddressSync(FSM_MINT, userPk);
  const distributorAta = getAssociatedTokenAddressSync(FSM_MINT, DISTRIBUTOR.publicKey);
  const expectedAmount = parseHumanAmountToU64BigInt(FSM_AMOUNT_HUMAN, FSM_DECIMALS);

  const ixs = parsed.transaction.message.instructions || [];
  let matched = false;

  for (const ix of ixs) {
    if (ix?.program !== "spl-token") continue;
    const p = ix?.parsed;
    if (!p || p.type !== "transfer") continue;

    const info = p.info || {};
    // parsed amounts are strings in base units for spl-token transfer
    const amountStr = String(info.amount ?? "");
    if (!/^\d+$/.test(amountStr)) continue;

    const amount = BigInt(amountStr);
    const source = String(info.source ?? "");
    const destination = String(info.destination ?? "");
    const authority = String(info.authority ?? "");

    if (
      source === distributorAta.toBase58() &&
      destination === userAta.toBase58() &&
      authority === DISTRIBUTOR.publicKey.toBase58() &&
      amount === expectedAmount
    ) {
      matched = true;
      break;
    }
  }

  if (!matched) return { ok: false, reason: "Tx does not match expected FSM transfer" };
  return { ok: true };
}

app.get("/health", (_, res) => res.json({ ok: true }));

// Step 0: server issues challenge (nonce + message)
app.post("/challenge", async (req, res) => {
  try {
    const { wallet } = req.body || {};
    if (!wallet) return res.status(400).json({ error: "wallet required" });

    const userPk = new PublicKey(wallet);
    void userPk; // validate pubkey format

    const db = loadDb();
    cleanupDb(db);

    if (db.claimed[wallet]) {
      return res.json({ alreadyClaimed: true, weekId: db.weekId });
    }

    const nonce = bs58.encode(nacl.randomBytes(16)); // server nonce
    const expiresAt = nowMs() + CHALLENGE_TTL_MS;
    const message = buildClaimMessage(wallet, nonce, db.weekId, expiresAt);

    db.challenges[wallet] = { nonce, expiresAt, message };
    saveDb(db);

    return res.json({ message, nonce, expiresAt, weekId: db.weekId });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// Step 1: client sends signature of server message; server returns fully signed tx
app.post("/claim", async (req, res) => {
  const { wallet, signature } = req.body || {};

  try {
    if (!wallet || !signature) {
      return res.status(400).json({ error: "wallet, signature required" });
    }

    const userPk = new PublicKey(wallet);

    const db = loadDb();
    cleanupDb(db);

    if (db.claimed[wallet]) {
      return res.json({ alreadyClaimed: true, weekId: db.weekId });
    }

    const ch = db.challenges[wallet];
    if (!ch) {
      return res.status(400).json({ error: "No active challenge. Call /challenge first." });
    }
    if (nowMs() > ch.expiresAt) {
      delete db.challenges[wallet];
      saveDb(db);
      return res.status(400).json({ error: "Challenge expired. Call /challenge again." });
    }

    if (!verifySignatureBs58({ userPubkey: wallet, message: ch.message, signature })) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    if (db.pending[wallet]) {
      return res.status(429).json({ error: "Claim already pending for this wallet" });
    }

    // Mark pending + consume challenge (one-time)
    db.pending[wallet] = { at: nowMs(), expiresAt: nowMs() + PENDING_TTL_MS };
    delete db.challenges[wallet];
    saveDb(db);

    const distributorAta = getAssociatedTokenAddressSync(FSM_MINT, DISTRIBUTOR.publicKey);
    const userAta = getAssociatedTokenAddressSync(FSM_MINT, userPk);

    const ixs = [];

    // 1) Ensure user's ATA exists (idempotent)
    ixs.push(
      createAssociatedTokenAccountIdempotentInstruction(
        DISTRIBUTOR.publicKey, // payer
        userAta,               // ata
        userPk,                // owner
        FSM_MINT               // mint
      )
    );

    // 2) Transfer FSM
    const amount = parseHumanAmountToU64BigInt(FSM_AMOUNT_HUMAN, FSM_DECIMALS);
    ixs.push(
      createTransferInstruction(
        distributorAta,         // source
        userAta,                // destination
        DISTRIBUTOR.publicKey,  // authority
        amount                  // u64 amount (BigInt)
      )
    );

    const { blockhash, lastValidBlockHeight } =
    await getLatestBlockhashWithRetry();

    const tx = new Transaction({
      feePayer: DISTRIBUTOR.publicKey,
      blockhash,
      lastValidBlockHeight,
    }).add(...ixs);

    tx.sign(DISTRIBUTOR);

    const txBase64 = tx.serialize().toString("base64");
    return res.json({ txBase64, weekId: db.weekId });
  } catch (e) {
    try {
      if (wallet) {
        const db = loadDb();
        delete db.pending[wallet];
        saveDb(db);
      }
    } catch {}

    return res.status(500).json({ error: String(e?.message || e) });
  }
});

app.post("/submit", async (req, res) => {
  try {
    const { wallet, txBase64 } = req.body || {};
    if (!wallet || !txBase64) return res.status(400).json({ error: "wallet, txBase64 required" });

    const db = loadDb();
    cleanupDb(db);

    if (!db.pending[wallet]) {
      return res.status(400).json({ error: "No pending claim for this wallet" });
    }

    const tx = Transaction.from(Buffer.from(String(txBase64), "base64"));

    // send from backend (Helius RPC), not browser
    const txSig = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false });

    return res.json({ txSig, weekId: db.weekId });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// Step 2: client confirms after sending tx; server verifies tx content
app.post("/confirm", async (req, res) => {
  try {
    const { wallet, txSig } = req.body || {};
    if (!wallet || !txSig) return res.status(400).json({ error: "wallet, txSig required" });

    const db = loadDb();
    cleanupDb(db);

    if (db.claimed[wallet]) return res.json({ ok: true, weekId: db.weekId });

    if (!db.pending[wallet]) {
      return res.status(400).json({ error: "No pending claim for this wallet" });
    }

    const st = await connection.getSignatureStatus(txSig, { searchTransactionHistory: true });
    const cs = st?.value?.confirmationStatus;
    const ok = cs === "confirmed" || cs === "finalized";
    if (!ok) return res.status(400).json({ error: "Transaction not confirmed yet" });

    const v = await validateTransferTx({ txSig, userWallet: wallet });
    if (!v.ok) return res.status(400).json({ error: v.reason });

    db.claimed[wallet] = { txSig, at: nowMs() };
    delete db.pending[wallet];
    saveDb(db);

    return res.json({ ok: true, weekId: db.weekId });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

const PORT = Number(process.env.PORT || "3000");
app.listen(PORT, () => {
  console.log(`FSM claim backend listening on :${PORT}`);
  console.log(`Distributor: ${DISTRIBUTOR.publicKey.toBase58()}`);
  console.log(`Mint: ${FSM_MINT.toBase58()}`);
  console.log(`WeekId: ${currentWeekIdUTC()}`);
});