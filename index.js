// index.js — minimal FSM claim backend (Railway)
// Node 18+
//
// Endpoints:
//   POST /claim   -> returns { txBase64, message, alreadyClaimed? }
//   POST /confirm -> returns { ok: true } after client submits tx
//
// Env vars required:
//   RPC_URL=...
//   FSM_MINT=7Admm1BZYi91xaS54D3ELnbP78VM1a1creUe2uVcibZ2
//   FSM_DECIMALS=6
//   FSM_AMOUNT=1                 // "1 FSM" (human units)
//   DISTRIBUTOR_SECRET_KEY=[...] // Solana keypair secretKey array (JSON), e.g. from `solana-keygen grind`
//   ALLOWED_ORIGIN=https://lockrion.com  (optional)
//   PORT=3000 (Railway provides)

// --- deps ---
// npm i express cors tweetnacl bs58 @solana/web3.js @solana/spl-token

import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import nacl from "tweetnacl";
import { PublicKey, Connection, Keypair, Transaction, SystemProgram } from "@solana/web3.js";
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

// simple local store (works on a single instance).
// If you scale to multiple instances, switch to Redis.
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.cwd();
const CLAIMS_FILE = path.join(DATA_DIR, "claims.json");

function loadClaims() {
  try {
    return JSON.parse(fs.readFileSync(CLAIMS_FILE, "utf8"));
  } catch {
    return { claimed: {}, pending: {} };
  }
}
function saveClaims(db) {
  fs.writeFileSync(CLAIMS_FILE, JSON.stringify(db, null, 2));
}

function u64Amount(human, decimals) {
  // integer math, safe for small airdrop amounts
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

function verifySignature({ userPubkey, message, signatureBase58 }) {
  const pubkey = new PublicKey(userPubkey);
  const msgBytes = new TextEncoder().encode(message);
  const sigBytes = Uint8Array.from(Buffer.from(signatureBase58, "base58")); // won't work (Buffer doesn't support base58)
  // use bs58:
}

import bs58 from "bs58";

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

// Step 1: create and return partially-signed transfer tx
app.post("/claim", async (req, res) => {
  try {
    const { wallet, signature, nonce } = req.body || {};
    if (!wallet || !signature || !nonce) {
      return res.status(400).json({ error: "wallet, signature, nonce required" });
    }

    const userPk = new PublicKey(wallet);

    // idempotency / gating
    const db = loadClaims();
    if (db.claimed[wallet]) {
      return res.json({ alreadyClaimed: true });
    }

    const message = buildClaimMessage(wallet, String(nonce));

    if (!verifySignatureBs58({ userPubkey: wallet, message, signature })) {
      return res.status(400).json({ error: "Invalid signature" });
    }

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
          userAta,               // ata
          userPk,                // owner
          FSM_MINT               // mint
        )
      );
    }

    const amount = u64Amount(FSM_AMOUNT_HUMAN, FSM_DECIMALS);
    ixs.push(
      createTransferInstruction(
        distributorAta,
        userAta,
        DISTRIBUTOR.publicKey,
        amount
      )
    );

    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");

    const tx = new Transaction({
      feePayer: userPk, // user pays fee (tiny). If you want distributor to pay: set feePayer=DISTRIBUTOR.publicKey
      blockhash,
      lastValidBlockHeight,
    }).add(...ixs);

    // If feePayer is user, only distributor signs the transfer authority
    // (user will sign as fee payer when submitting)
    tx.partialSign(DISTRIBUTOR);

    const txBase64 = tx.serialize({ requireAllSignatures: false }).toString("base64");
    return res.json({ txBase64, message });
  } catch (e) {
    // clean pending on error
    try {
      const { wallet } = req.body || {};
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

    // verify tx exists on chain (confirmed)
    const st = await connection.getSignatureStatus(txSig, { searchTransactionHistory: true });
    const ok = st?.value?.confirmationStatus === "confirmed" || st?.value?.confirmationStatus === "finalized";
    if (!ok) return res.status(400).json({ error: "Transaction not confirmed yet" });

    db.claimed[wallet] = { txSig, at: Date.now() };
    delete db.pending[wallet];
    saveClaims(db);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

const PORT = Number(process.env.PORT || "3000");
app.listen(PORT, () => {
  console.log(`FSM claim backend listening on :${PORT}`);
  console.log(`Distributor: ${DISTRIBUTOR.publicKey.toBase58()}`);
  console.log(`Mint: ${FSM_MINT.toBase58()}`);
});
