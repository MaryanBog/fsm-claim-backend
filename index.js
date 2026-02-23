// index.js — minimal FSM claim backend (Render)
// Node 18+
//
// Endpoints:
//   GET  /health   -> { ok: true }
//   POST /claim    -> returns { txBase64, message, alreadyClaimed?, weekId? }
//   POST /confirm  -> returns { ok: true } after client submits tx
//
// Env vars required:
//   RPC_URL=...
//   FSM_MINT=7Admm1BZYi91xaS54D3ELnbP78VM1a1creUe2uVcibZ2
//   FSM_DECIMALS=6
//   FSM_AMOUNT=1
//   DISTRIBUTOR_SECRET_KEY=[...]  // Solana keypair secretKey array JSON
//   ALLOWED_ORIGIN=https://lockrion.com (optional)
//   PORT=3000 (Render provides)

// --- deps ---
// npm i express cors tweetnacl bs58 @solana/web3.js @solana/spl-token

import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { PublicKey, Connection, Keypair, Transaction } from "@solana/web3.js";
import {
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
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
const FSM_AMOUNT_HUMAN = Number(process.env.FSM_AMOUNT ?? "1");

const distributorSecret = JSON.parse(mustEnv("DISTRIBUTOR_SECRET_KEY"));
const DISTRIBUTOR = Keypair.fromSecretKey(Uint8Array.from(distributorSecret));

const connection = new Connection(RPC_URL, "confirmed");

// Store claims locally (weekly reset).
// NOTE: On Render Free this filesystem may reset on redeploy/restart.
// Weekly reset is handled logically by weekId.
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.cwd();
const CLAIMS_FILE = path.join(DATA_DIR, "claims.json");

function currentWeekIdUTC() {
  // Week counter within year (simple, deterministic; good enough for weekly reset)
  const d = new Date();
  const year = d.getUTCFullYear();
  const start = new Date(Date.UTC(year, 0, 1));
  const day = Math.floor((d - start) / 86400000) + 1;
  const week = Math.ceil(day / 7);
  return `${year}-W${String(week).padStart(2, "0")}`;
}

function loadClaims() {
  const weekId = currentWeekIdUTC();
  try {
    const db = JSON.parse(fs.readFileSync(CLAIMS_FILE, "utf8"));

    // Weekly reset
    if (!db.weekId || db.weekId !== weekId) {
      return { weekId, claimed: {}, pending: {} };
    }

    return {
      weekId,
      claimed: db.claimed || {},
      pending: db.pending || {},
    };
  } catch {
    return { weekId, claimed: {}, pending: {} };
  }
}

function saveClaims(db) {
  fs.writeFileSync(CLAIMS_FILE, JSON.stringify(db, null, 2));
}

function u64Amount(human, decimals) {
  const factor = 10 ** decimals;
  const v = Math.round(human * factor);
  if (!Number.isFinite(v) || v <= 0) throw new Error("Invalid amount");
  return BigInt(v);
}

// Message user signs (no SOL, just signature)
function buildClaimMessage(userPubkey, nonce) {
  return [
    "Flexion Support Mark (FSM) — Claim",
    "I am claiming FSM as a symbolic on-chain support badge.",
    `Wallet: ${userPubkey}`,
    `Nonce: ${nonce}`,
    "No sale. No exchange. No expectations of profit.",
  ].join("\n");
}

function verifySignatureBs58({ userPubkey, message, signature }) {
  const pubkey = new PublicKey(userPubkey);
  const msgBytes = new TextEncoder().encode(message);
  const sigBytes = bs58.decode(signature);
  return nacl.sign.detached.verify(msgBytes, sigBytes, pubkey.toBytes());
}

async function ataExists(ata) {
  const info = await connection.getAccountInfo(ata, "confirmed");
  return !!info;
}

app.get("/health", (_, res) => res.json({ ok: true }));

// Step 1: create and return fully-signed transfer tx (distributor pays fees)
app.post("/claim", async (req, res) => {
  const { wallet, signature, nonce } = req.body || {};

  try {
    if (!wallet || !signature || !nonce) {
      return res.status(400).json({ error: "wallet, signature, nonce required" });
    }

    const userPk = new PublicKey(wallet);

    // weekly-scoped gating
    const db = loadClaims();
    if (db.claimed[wallet]) {
      return res.json({ alreadyClaimed: true, weekId: db.weekId });
    }

    const message = buildClaimMessage(wallet, String(nonce));

    // Reserve "pending" to prevent rapid double-claims
    if (db.pending[wallet]) {
      return res.status(429).json({ error: "Claim already pending for this wallet" });
    }
    db.pending[wallet] = { at: Date.now() };
    saveClaims(db);

    // Build token transfer
    const distributorAta = getAssociatedTokenAddressSync(FSM_MINT, DISTRIBUTOR.publicKey);
    const userAta = getAssociatedTokenAddressSync(FSM_MINT, userPk);

    const ixs = [];

    // Create user's ATA if missing (paid by distributor)
    if (!(await ataExists(userAta))) {
      ixs.push(
        createAssociatedTokenAccountInstruction(
          DISTRIBUTOR.publicKey, // payer
          userAta, // ata
          userPk, // owner
          FSM_MINT // mint
        )
      );
    }

    const amount = u64Amount(FSM_AMOUNT_HUMAN, FSM_DECIMALS);
    ixs.push(createTransferInstruction(distributorAta, userAta, DISTRIBUTOR.publicKey, amount));

    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");

    // Distributor pays the network fee -> user needs 0 SOL
    const tx = new Transaction({
      feePayer: DISTRIBUTOR.publicKey,
      blockhash,
      lastValidBlockHeight,
    }).add(...ixs);

    // Fully sign with distributor (fee payer + transfer authority + ATA payer)
    tx.sign(DISTRIBUTOR);

    const txBase64 = tx.serialize().toString("base64");
    return res.json({ txBase64, message, weekId: db.weekId });
  } catch (e) {
    // clean pending on error
    try {
      if (wallet) {
        const db = loadClaims();
        delete db.pending[wallet];
        saveClaims(db);
      }
    } catch {}

    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// Step 2: client calls this AFTER submitting tx (with tx signature)
app.post("/confirm", async (req, res) => {
  try {
    const { wallet, txSig } = req.body || {};
    if (!wallet || !txSig) return res.status(400).json({ error: "wallet, txSig required" });

    const db = loadClaims();
    if (!db.pending[wallet] && !db.claimed[wallet]) {
      return res.status(400).json({ error: "No pending claim for this wallet" });
    }

    const st = await connection.getSignatureStatus(txSig, { searchTransactionHistory: true });
    const ok =
      st?.value?.confirmationStatus === "confirmed" || st?.value?.confirmationStatus === "finalized";
    if (!ok) return res.status(400).json({ error: "Transaction not confirmed yet" });

    db.claimed[wallet] = { txSig, at: Date.now() };
    delete db.pending[wallet];
    saveClaims(db);

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