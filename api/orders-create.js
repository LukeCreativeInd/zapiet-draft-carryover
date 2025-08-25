// Serverless function for Vercel (Node 18, ESM)
// Endpoint: POST /api/orders-create
// Copies Zapiet fields from originating draft to the order's note_attributes.

import crypto from "node:crypto";

// ---- Helpers ----
async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function timingSafeEqual(a, b) {
  const ab = Buffer.from(a || "", "utf8");
  const bb = Buffer.from(b || "", "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function mergeNoteAttributes(existing = [], incoming = []) {
  const out = [...existing];
  const idx = new Map();
  out.forEach((a, i) => a?.name && idx.set(a.name, i));
  for (const a of incoming) {
    if (!a?.name) continue;
    const i = idx.get(a.name);
    if (i == null) out.push({ name: a.name, value: a.value ?? "" });
    else out[i] = { name: a.name, value: a.value ?? "" };
  }
  return out;
}

function differs(a1, a2) {
  return JSON.stringify(a1 ?? []) !== JSON.stringify(a2 ?? []);
}

async function shopifyGET(env, path) {
  const res = await fetch(`https://${env.SHOP_DOMAIN}${path}`, {
    method: "GET",
    headers: { "X-Shopify-Access-Token": env.ADMIN_API_TOKEN }
  });
  return res;
}

async function shopifyPUT(env, path, body) {
  const res = await fetch(`https://${env.SHOP_DOMAIN}${path}`, {
    method: "PUT",
    headers: {
      "X-Shopify-Access-Token": env.ADMIN_API_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  return res;
}

// ---- Handler ----
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(200).send("OK");
  }

  // 1) Verify HMAC
  const raw = await readRawBody(req);
  const secret = process.env.WEBHOOK_SECRET; // from your custom app: "Webhook signing secret"
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  if (!secret || !hmacHeader) {
    return res.status(401).send("Missing secret or hmac");
  }
  const digest = crypto
    .createHmac("sha256", secret)
    .update(raw)
    .digest("base64");
  if (!timingSafeEqual(digest, hmacHeader)) {
    return res.status(401).send("Bad HMAC");
  }

  // 2) Parse webhook
  let order;
  try { order = JSON.parse(raw.toString("utf8")); }
  catch { return res.status(400).send("Bad JSON"); }

  const orderId = order?.id;
  if (!orderId) {
    // Always 200 so Shopify doesn’t retry forever
    return res.status(200).send("No order id");
  }

  // 3) GET order (to read draft_order_id + existing note_attributes)
  const oResp = await shopifyGET(process.env, `/admin/api/2025-01/orders/${orderId}.json`);
  if (!oResp.ok) return res.status(200).send("GET order failed");
  const fullOrder = await oResp.json();
  const draftId = fullOrder?.order?.draft_order_id;
  if (!draftId) {
    // If Samita sometimes creates orders without a draft link, nothing to do
    return res.status(200).send("No draft link");
  }

  // 4) GET draft (to read Zapiet attrs)
  const dResp = await shopifyGET(process.env, `/admin/api/2025-01/draft_orders/${draftId}.json`);
  if (!dResp.ok) return res.status(200).send("GET draft failed");
  const draft = await dResp.json();

  const wanted = new Set(["Delivery-Location-Id","Delivery-Date","Checkout-Method"]);
  const draftAttrs = (draft?.draft_order?.note_attributes || []).filter(a => wanted.has(a?.name));
  if (!draftAttrs.length) {
    return res.status(200).send("No Zapiet attrs on draft");
  }

  // 5) Merge + update order note_attributes
  const existing = fullOrder?.order?.note_attributes || [];
  const merged = mergeNoteAttributes(existing, draftAttrs);
  if (!differs(existing, merged)) {
    return res.status(200).send("No changes needed");
  }

  const putResp = await shopifyPUT(
    process.env,
    `/admin/api/2025-01/orders/${orderId}.json`,
    { order: { id: orderId, note_attributes: merged } }
  );
  // Always 200 to acknowledge webhook; log failures in Vercel logs if any
  if (!putResp.ok) {
    const txt = await putResp.text().catch(() => "");
    console.log("PUT order failed", putResp.status, txt);
  }
  return res.status(200).send("Done");
}

// Disable Vercel's default body parsing so we can verify HMAC on the raw body
export const config = {
  api: { bodyParser: false }
};
