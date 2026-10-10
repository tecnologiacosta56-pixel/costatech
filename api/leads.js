
import { cert, getApps, initializeApp } from "firebase-admin/app";
import {
  FieldValue,
  getFirestore,
} from "firebase-admin/firestore";

const ALLOWED_ORIGINS = new Set([
  "https://costatech.vercel.app",
]);

function clean(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function getDatabase() {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw) {
    throw new Error("Firebase credentials not configured");
  }

  const serviceAccount = JSON.parse(raw);

  if (serviceAccount.project_id !== "costa-orcamentos") {
    throw new Error("Unexpected Firebase project");
  }

  const existingApp = getApps().find(
    (app) => app.name === "[DEFAULT]"
  );

  const app = existingApp || initializeApp({
    credential: cert(serviceAccount),
  });

  return getFirestore(app);
}

async function verifyTurnstile(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;

  if (!secret || !token) return false;

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        secret,
        response: token,
      }),
    }
  );

  if (!response.ok) return false;

  const result = await response.json();

  return (
    result.success === true &&
    result.hostname === "costatech.vercel.app"
  );
}

export default async function handler(req, res) {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    if (!origin || !ALLOWED_ORIGINS.has(origin)) {
      return res.status(403).end();
    }
    return res.status(204).end();
  }

  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: "Origin not allowed" });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ error: "Invalid request" });
    }

    if (clean(body.website, 200)) {
      return res.status(400).json({ error: "Invalid submission" });
    }

    const token = clean(body.turnstileToken, 2048);

    if (!token) {
      return res.status(400).json({
        error: "Security verification required",
      });
    }

    const verified = await verifyTurnstile(token);

    if (!verified) {
      return res.status(403).json({
        error: "Security verification failed",
      });
    }

    const nome = clean(body.name, 120);
    const email = clean(body.email, 254);

    if (
      !nome ||
      !email ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: "Name and valid email are required",
      });
    }

    const lead = {
      nome,
      email,
      telefone: clean(body.phone, 40),
      whatsapp: clean(body.whatsapp, 40),
      cidade: clean(body.city, 120),
      empresa: clean(body.company, 160),
      segmento: clean(body.segment, 120),
      servico: clean(body.service, 160),
      mensagem: clean(body.message, 3000),
      origem: "Landing Page",
      status: "Novo",
      createdAt: FieldValue.serverTimestamp(),
    };

    const db = getDatabase();
    const doc = await db.collection("leads").add(lead);

    return res.status(201).json({
      success: true,
      id: doc.id,
    });
  } catch (error) {
    console.error("Lead submission failed:", error.message);

    return res.status(500).json({
      error: "Could not save lead",
    });
  }
}
