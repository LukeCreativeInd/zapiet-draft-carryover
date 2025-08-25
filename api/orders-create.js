// Serverless function for Vercel (Node 18/20/22)
// Endpoint: POST /api/orders-create
// Copies Zapiet fields from originating draft to the order's note_attributes,
// but only if the order is tagged "samita-wholesale".

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
  return fetch(`https://${env.SHOP_DOMAIN}${path}`, {
    method: "GET",
    headers: { "X-Shopify-Access-Token": env.ADMIN_API_TOKEN }
  });
}

async function shopifyPUT(env, path, body) {
  return fetch(`https://${env.SHOP_DOMAIN}${path}`, {
    method: "PUT",
    headers: {
      "X-Shopify-Access-Token": env.ADMIN_API_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
}

// ---- Handler ----
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(200).send("OK");
  }

  const raw = await readRawBody(req);

  // 1) Verify HMAC
  const secret = process.env.WEBHOOK_SECRET;
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  if (!secret || !hmacHeader) {
    console.log("[Webhook] Missing secret or HMAC header");
    return res.status(401).send("Missing secret or hmac");
  }
  const digest = crypto.createHmac("sha256", secret).update(raw).digest("base64");
  if (!timingSafeEqual(digest, hmacHeader)) {
    console.log("[Webhook] Bad HMAC");
    return res.status(401).send("Bad HMAC");
  }

  // 2) Parse webhook body
  let order;
  try {
    order = JSON.parse(raw.toString("utf8"));
  } catch (e) {
    console.log("[Webhook] Bad JSON parse", e);
    return res.status(400).send("Bad JSON");
  }

  const orderId = order?.id;
  console.log("[Webhook] Received order id:", orderId);
  if (!orderId) return res.status(200).send("No order id");

  // 3) GET order (for tags + draft_order_id + existing note_attributes)
  const oResp = await shopifyGET(process.env, `/admin/api/2025-01/orders/${orderId}.json`);
  if (!oResp.ok) {
    console.log("[Webhook] GET order failed", oResp.status);
    return res.status(200).send("GET order failed");
  }
  const fullOrder = await oResp.json();

  const tags = (fullOrder?.order?.tags || "").toLowerCase();
  console.log("[Webhook] Order tags:", tags);

  if (!tags.includes("samita-wholesale")) {
    console.log("[Webhook] Not a Samita order, skipping");
    return res.status(200).send("Not a Samita order");
  }

  const draftId = fullOrder?.order?.draft_order_id;
  console.log("[Webhook] Draft id:", draftId);

  if (!draftId) {
    console.log("[Webhook] No draft link on order");
    return res.status(200).send("No draft link");
  }

  // 4) GET draft
  const dResp = await shopifyGET(process.env, `/admin/api/2025-01/draft_orders/${draftId}.json`);
  if (!dResp.ok) {
    console.log("[Webhook] GET draft failed", dResp.status);
    return res.status(200).send("GET draft failed");
  }
  const draft = await dResp.json();

  const wanted = new Set(["Delivery-Location-Id","Delivery-Date","Checkout-Method"]);
  const draftAttrs = (draft?.draft_order?.note_attributes || []).filter(a => wanted.has(a?.name));

  console.log("[Webhook] Draft note_attributes:", draftAttrs);

  if (!draftAttrs.length) {
    console.log("[Webhook] No Zapiet attrs found on draft");
    return res.status(200).send("No Zapiet attrs on draft");
  }

  // 5) Merge with existing
  const existing = fullOrder?.order?.note_attributes || [];
  const merged = mergeNoteAttributes(existing, draftAttrs);
  console.log("[Webhook] Existing attrs:", existing);
  console.log("[Webhook] Merged attrs:", merged);

  if (!differs(existing, merged)) {
    console.log("[Webhook] No changes needed");
    return res.status(200).send("No changes needed");
  }

  // 6) PUT order to update
  const putResp = await shopifyPUT(
    process.env,
    `/admin/api/2025-01/orders/${orderId}.json`,
    { order: { id: orderId, note_attributes: merged } }
  );

  if (!putResp.ok) {
    const txt = await putResp.text().catch(() => "");
    console.log("[Webhook] PUT order failed", putResp.status, txt);
  } else {
    console.log("[Webhook] Order updated successfully");
  }

  return res.status(200).send("Done");
}

// Disable Vercel body parsing so we can verify raw HMAC
export const config = {
  api: { bodyParser: false }
};
