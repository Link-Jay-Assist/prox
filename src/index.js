import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import crypto from "crypto";
import { RateLimiterMemory } from "rate-limiter-flexible";
import { request as ureq, fetch, Agent, setGlobalDispatcher } from "undici";

/**
 * PERF: keep-alive / connection pooling (sneller, zelfde werking)
 */
setGlobalDispatcher(
  new Agent({
    connections: 50,
    pipelining: 1,
    keepAliveTimeout: 30_000,
    keepAliveMaxTimeout: 120_000,
  })
);

/**
 * SECURITY: TLS bypass UIT
 * (FileMaker heeft nu geldig cert, dus dit hoort weg)
 */
// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const {
  PORT = 3000,
  API_SECRET,
  FM_HOST,
  FM_DB,
  FM_USER,
  FM_PASS,
  FM_TOKEN_TTL_MIN = 12,
  ALLOW_ORIGIN,
  TRUST_PROXY_HOPS = "1",
} = process.env;

if (!API_SECRET || !FM_HOST || !FM_DB || !FM_USER || !FM_PASS) {
  console.error("Missing env vars");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", Math.max(0, parseInt(TRUST_PROXY_HOPS, 10) || 1));
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(express.json({ limit: "10mb" }));

// ⭐ CORS – meerdere origins via komma-gescheiden lijst in ALLOW_ORIGIN
app.use(
  cors({
    origin: ALLOW_ORIGIN ? ALLOW_ORIGIN.split(",").map((s) => s.trim()) : true,
  })
);

app.use(morgan("tiny"));

const limiter = new RateLimiterMemory({ points: 60, duration: 60 });
app.use(async (req, res, next) => {
  try {
    await limiter.consume(req.ip);
    next();
  } catch {
    res.status(429).json({ error: "Too many requests" });
  }
});

let cachedToken = null;
let tokenExp = 0;

// ✅ Hardcoded layout (zoals jij wil)
const LAYOUT_SERVICEBON = "REST_Servicebon";

// ✅ default find criteria zodat je NOOIT “Find criteria are empty” krijgt
const DEFAULT_FIND_CRITERIA = { g_api_enabled: "*" };

// ---------- GENERIEKE FETCH HELPER (met timeout, zelfde output) ----------
async function jsonFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);

  try {
    const r = await ureq(url, { ...opts, signal: controller.signal });
    const t = await r.body.text();

    try {
      return { status: r.statusCode, json: JSON.parse(t) };
    } catch {
      return { status: r.statusCode, json: { raw: t } };
    }
  } finally {
    clearTimeout(timeout);
  }
}

// ---------- FILEMAKER TOKEN OPHALEN ----------
async function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExp) return cachedToken;

  const basic = Buffer.from(`${FM_USER}:${FM_PASS}`).toString("base64");

  const { status, json } = await jsonFetch(
    `${FM_HOST}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}/sessions`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    }
  );

  if (status !== 200 || !json?.response?.token) {
    const msg = json?.messages?.[0]?.message || "unknown";
    throw new Error(`FM login failed: ${status} ${msg}`);
  }

  cachedToken = json.response.token;
  tokenExp = now + Number(FM_TOKEN_TTL_MIN) * 60 * 1000;
  return cachedToken;
}

// ---------- AUTH HELPER (timing-safe) ----------
function safeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function okAuth(req) {
  const s = (req.header("X-Webhook-Secret") || "").trim();
  const b = (req.header("Authorization") || "").trim();
  const bearer = b.startsWith("Bearer ") ? b.slice(7).trim() : "";

  return safeEq(s, API_SECRET) || safeEq(bearer, API_SECRET);
}

/**
 * ✅ Script runner via records (GET) – jouw “werkt altijd”
 */
async function runScriptViaRecords({
  scriptName,
  payloadObj,
  layout = LAYOUT_SERVICEBON,
}) {
  if (!scriptName) throw new Error("scriptName is required");

  const token = await getToken();

  const payloadString = JSON.stringify(
    payloadObj && typeof payloadObj === "object" ? payloadObj : {}
  );

  const url =
    `${FM_HOST}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}` +
    `/layouts/${encodeURIComponent(layout)}/records` +
    `?_limit=1` +
    `&script=${encodeURIComponent(scriptName)}` +
    `&script.param=${encodeURIComponent(payloadString)}`;

  const call = async (tok) =>
    jsonFetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${tok}`,
        "Content-Type": "application/json",
      },
    });

  let r = await call(token);
  if (r.status === 401) {
    cachedToken = null;
    r = await call(await getToken());
  }
  return r;
}

/**
 * ✅ Script runner via _find (POST) met niet-lege criteria + script.param
 */
async function runScriptViaFind({
  scriptName,
  payloadObj,
  layout = LAYOUT_SERVICEBON,
  findCriteria = DEFAULT_FIND_CRITERIA,
  limit = 1,
}) {
  if (!scriptName) throw new Error("scriptName is required");

  const token = await getToken();

  const payloadString = JSON.stringify(
    payloadObj && typeof payloadObj === "object" ? payloadObj : {}
  );

  const url =
    `${FM_HOST}/fmi/data/vLatest/databases/${encodeURIComponent(FM_DB)}` +
    `/layouts/${encodeURIComponent(layout)}/_find`;

  const bodyObj = {
    query: [findCriteria || DEFAULT_FIND_CRITERIA],
    limit: Math.max(1, Number(limit) || 1),
    script: scriptName,
    "script.param": payloadString,
  };

  const call = async (tok) =>
    jsonFetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tok}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(bodyObj),
    });

  let r = await call(token);
  if (r.status === 401) {
    cachedToken = null;
    r = await call(await getToken());
  }
  return r;
}

// ---------- ROUTES ----------
app.get("/health", (_, res) => res.type("text/plain").send("OK"));

/* 🧪 TEST ROUTE — check outbound connectivity */
app.get("/test", async (_req, res) => {
  try {
    const response = await fetch("https://www.google.com");
    const html = await response.text();
    res
      .status(200)
      .send(
        `Connected!<br>Status: ${response.status}<br><pre>${html.substring(
          0,
          300
        )}...</pre>`
      );
  } catch (err) {
    res.status(500).send(`Connection failed: ${err.message}`);
  }
});

/* 🌐 GET public IP */
app.get("/whois-ip", async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: "unauthorized" });

    const endpoints = [
      "https://api.ipify.org?format=json",
      "https://ifconfig.me/all.json",
      "https://checkip.amazonaws.com/",
    ];

    for (const url of endpoints) {
      try {
        const r = await fetch(url);
        if (!r.ok) continue;
        const text = await r.text();
        try {
          const j = JSON.parse(text);
          const ip = j.ip || j.ip_addr || j.ip_address;
          if (ip) return res.json({ ip });
        } catch {
          const cand = text.trim();
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cand))
            return res.json({ ip: cand });
        }
      } catch {}
    }

    res.status(502).json({ error: "could not determine IP" });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🔍 Debiteur zoeken (ZOEKSTUK TERUG ZOALS HET WAS) */
app.get("/debiteur/search", async (req, res) => {
  const qRaw = (req.query.q || "").toString();
  const q = qRaw.trim();
  if (!q) return res.status(400).json({ error: "q (search term) is required" });

  const isNumeric = /^[0-9]+$/.test(q);
  const wildcard = `*${q}*`;

  try {
    const token = await getToken();

    // ✅ TERUG: exact dezelfde query-opbouw als je originele versie
    // (dus debiteurNummer: q zonder '==')
    const baseQuery = [];
    if (isNumeric) baseQuery.push({ debiteurNummer: q });
    baseQuery.push({ debiteurNaam: wildcard });

    const callFind = async (query) =>
      jsonFetch(
        `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Debiteur_Rest/_find`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ query, limit: 50 }),
        }
      );

    let { status, json } = await callFind(baseQuery);
    let fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === "0") {
      const records = json?.response?.data || [];
      return res.json(
        records.map((rec) => ({
          recordId: rec.recordId,
          debiteurNummer: rec.fieldData.debiteurNummer,
          debiteurNaam: rec.fieldData.debiteurNaam,
          telefoon: rec.fieldData.algTelefoon,
          email: rec.fieldData.algEmail,
        }))
      );
    }

    if (!(status === 200 && fmCode === "401")) {
      console.error(
        "FileMaker error in baseQuery:",
        status,
        JSON.stringify(json)
      );
      return res.status(502).json({ error: "no matches" });
    }

    const addressQuery = [
      { "debiteur_ADRESSEN::Adres": wildcard },
      { "debiteur_ADRESSEN::Plaats": wildcard },
      { "debiteur_ADRESSEN::Postcode": wildcard },
    ];

    const second = await callFind(addressQuery);
    status = second.status;
    json = second.json;
    fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === "0") {
      const records = json?.response?.data || [];
      return res.json(
        records.map((rec) => ({
          recordId: rec.recordId,
          debiteurNummer: rec.fieldData.debiteurNummer,
          debiteurNaam: rec.fieldData.debiteurNaam,
          telefoon: rec.fieldData.algTelefoon,
          email: rec.fieldData.algEmail,
        }))
      );
    }

    if (status === 200 && fmCode === "401")
      return res.json({ error: "no matches" });

    console.error(
      "FileMaker error in addressQuery:",
      status,
      JSON.stringify(json)
    );
    return res.json({ error: "no matches" });
  } catch (err) {
    console.error("Error in /debiteur/search:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🏠 Debiteur adres ophalen */
app.get("/debiteur/address", async (req, res) => {
  const debiteurNummer = (req.query.debiteurNummer || "").toString().trim();
  if (!debiteurNummer)
    return res.status(400).json({ error: "debiteurNummer is required" });

  try {
    const token = await getToken();

    const { status, json } = await jsonFetch(
      `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Debiteur_Rest/_find`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: [{ debiteurNummer }],
          limit: 1,
        }),
      }
    );

    const fmCode = json?.messages?.[0]?.code;
    if (status !== 200 || fmCode !== "0") return res.json({ address: null });

    const rec = json.response?.data?.[0];
    const fieldData = rec?.fieldData || {};
    const portals = rec?.portalData?.debiteur_ADRESSEN || [];

    if (!portals.length) {
      return res.json({
        debiteurNummer: fieldData.debiteurNummer ?? null,
        debiteurNaam: fieldData.debiteurNaam ?? null,
        address: null,
      });
    }

    const pick = (type) =>
      portals.find((p) => p["debiteur_ADRESSEN::adresType"] === type);

    const bezoek = pick("bezoek");
    const factuur = pick("factuur");
    const chosen = bezoek || factuur || portals[0];

    return res.json({
      debiteurNummer: fieldData.debiteurNummer ?? null,
      debiteurNaam: fieldData.debiteurNaam ?? null,
      address: {
        type: chosen["debiteur_ADRESSEN::adresType"] ?? null,
        straat: chosen["debiteur_ADRESSEN::straat"] ?? null,
        huisnummer: chosen["debiteur_ADRESSEN::huisnummer"] ?? null,
        toevoeging: chosen["debiteur_ADRESSEN::toevoeging"] ?? null,
        postcode: chosen["debiteur_ADRESSEN::postcode"] ?? null,
        plaats: chosen["debiteur_ADRESSEN::plaats"] ?? null,
        land: chosen["debiteur_ADRESSEN::land"] ?? null,
      },
    });
  } catch (err) {
    console.error("Error in /debiteur/address:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🔍 Servicebon zoeken */
app.get("/servicebon/search", async (req, res) => {
  const qRaw = (req.query.q || "").toString();
  const q = qRaw.trim();
  if (!q) return res.status(400).json({ error: "q (search term) is required" });

  const wildcard = `*${q}*`;

  try {
    const token = await getToken();

    const fmQuery = [
      { projectcode: wildcard },
      { projectNaam: wildcard },
      { "PROJECT::debiteurNaam": wildcard },
      { "PROJECT::debiteurNummer": wildcard },
      { "project_SERVICECONTRACTEN::contractNummer": wildcard },
      { "project_SERVICECONTRACTEN::machine": wildcard },
      { "project_SERVICECONTRACTEN::machineType": wildcard },
      { "PROJECT::adresLabelBezoek": wildcard },
      { "project_ADRESSEN~bezoek::straat": wildcard },
      { "project_ADRESSEN~bezoek::huisnummer": wildcard },
      { "project_ADRESSEN~bezoek::toevoeging": wildcard },
      { servicenummer: wildcard },
      { servicebonnummer: wildcard },
      { "project_SERVICENUMMER::omschrijvingKort": wildcard },
    ];

    const { status, json } = await jsonFetch(
      `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Servicebon_Rest/_find`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query: fmQuery, limit: 50 }),
      }
    );

    const fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === "0") {
      const records = json?.response?.data || [];
      const mapped = records.map((rec) => {
        const f = rec.fieldData || {};
        return {
          recordId: rec.recordId,
          projectcode: f.projectcode,
          projectNaam: f.projectNaam,
          debiteurNummer: f["PROJECT::debiteurNummer"],
          debiteurNaam: f["PROJECT::debiteurNaam"],
          adresLabelBezoek: f["PROJECT::adresLabelBezoek"],
          straat: f["project_ADRESSEN~bezoek::straat"] ?? null,
          huisnummer: f["project_ADRESSEN~bezoek::huisnummer"] ?? null,
          toevoeging: f["project_ADRESSEN~bezoek::toevoeging"] ?? null,
          contractNummer: f["project_SERVICECONTRACTEN::contractNummer"],
          contractCode: f["project_SERVICECONTRACTEN::contractCode"],
          machineCode: f["project_SERVICECONTRACTEN::machine"],
          machineType: f["project_SERVICECONTRACTEN::machineType"],
          servicenummerId: f.id_servicenummer,
          servicenummer: f.servicenummer,
          servicebonnummer: f.servicebonnummer,
          machineOmschrijving: f["project_SERVICENUMMER::omschrijvingKort"],
          meldingsdatum: f.__createDate,
          contractDatumStart: f["project_SERVICECONTRACTEN::datumStart"],
          contractDatumEinde: f["project_SERVICECONTRACTEN::datumEinde"],
        };
      });

      return res.json(mapped);
    }

    if (status === 200 && fmCode === "401") return res.json({ error: "no matches" });

    console.error(
      "FileMaker find error in /servicebon/search:",
      status,
      JSON.stringify(json)
    );
    return res.status(502).json({
      error: "FileMaker response error",
      fmStatus: status,
      fmMessages: json?.messages,
    });
  } catch (err) {
    console.error("Error in /servicebon/search:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🔍 Product zoeken */
app.get("/product/search", async (req, res) => {
  const qRaw = (req.query.q || "").toString();
  const q = qRaw.trim();

  const onlyStock =
    String(req.query.onlyStock || "").toLowerCase() === "true" ||
    String(req.query.onlyStock || "") === "1";

  const category = (req.query.category || "").toString().trim();

  const limitReq = Number(req.query.limit || 50);
  const limit = Number.isFinite(limitReq)
    ? Math.min(200, Math.max(1, limitReq))
    : 50;

  if (!q) return res.status(400).json({ error: "q (search term) is required" });

  const wildcard = `*${q}*`;

  try {
    const token = await getToken();

    const baseOr = [
      { productNummerIntern: wildcard },
      { productNummerLeverancier: wildcard },
      { omschrijvingKortNL: wildcard },
      { omschrijvingKortEN: wildcard },
      { omschrijvingKortDE: wildcard },
      { leverancierNaam: wildcard },
    ];

    const fmQuery = baseOr.map((row) => {
      const r = { ...row };
      if (category) r.productcategorie = category;
      if (onlyStock) r["product_VOORRAAD::aantal"] = ">0";
      return r;
    });

    const { status, json } = await jsonFetch(
      `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Product_rest/_find`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query: fmQuery, limit }),
      }
    );

    const fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === "0") {
      const records = json?.response?.data || [];
      return res.json(
        records.map((rec) => {
          const f = rec.fieldData || {};
          return {
            recordId: rec.recordId,
            productNummerIntern: f.productNummerIntern ?? null,
            productNummerLeverancier: f.productNummerLeverancier ?? null,
            leverancierNaam: f.leverancierNaam ?? null,
            productcategorie: f.productcategorie ?? null,
            productgroep: f.productgroep ?? null,
            omschrijvingKortNL: f.omschrijvingKortNL ?? null,
            omschrijvingKortEN: f.omschrijvingKortEN ?? null,
            omschrijvingKortDE: f.omschrijvingKortDE ?? null,
            omschrijvingLang: f.omschrijvingLang ?? null,
            merk: f.merk ?? null,
            locatiecode: f.locatiecode ?? null,
            inkoopprijs: f.inkoopprijs ?? null,
            inkoopprijs_waarde: f.inkoopprijs_waarde ?? null,
            voorraad: f["product_VOORRAAD::aantal"] ?? null,
            voorraadRecordId: f["product_VOORRAAD::ID"] ?? null,
            productId: f.ID ?? null,
            voorraadProductId: f["product_VOORRAAD::id_product"] ?? null,
          };
        })
      );
    }

    if (status === 200 && fmCode === "401") return res.json({ error: "no matches" });

    console.error(
      "FileMaker find error in /product/search:",
      status,
      JSON.stringify(json)
    );
    return res.status(502).json({
      error: "FileMaker response error",
      fmStatus: status,
      fmMessages: json?.messages,
    });
  } catch (err) {
    console.error("Error in /product/search:", err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

// ✅ Preview → FileMaker script: API_Servicebon_PREVIEW
app.post("/servicebon/preview", async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: "unauthorized" });

    const { status, json } = await runScriptViaRecords({
      scriptName: "API_Servicebon_PREVIEW",
      payloadObj: req.body,
      layout: LAYOUT_SERVICEBON,
    });

    return res.status(status).json(json);
  } catch (e) {
    console.error("Error in /servicebon/preview:", e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ✅ Receive → FileMaker script: API_Servicebon_RECEIVE
app.post("/servicebon/receive", async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: "unauthorized" });

    const { status, json } = await runScriptViaRecords({
      scriptName: "API_Servicebon_RECEIVE",
      payloadObj: req.body,
      layout: LAYOUT_SERVICEBON,
    });

    return res.status(status).json(json);
  } catch (e) {
    console.error("Error in /servicebon/receive:", e);
    return res.status(500).json({ error: String(e.message || e) });
  }
});

// ---------- HOOFDENDPOINT /fm/request (AUTH + minimale hardening) ----------
const ALLOWED_METHODS = new Set(["GET", "POST", "PATCH", "DELETE"]);

app.post("/fm/request", async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: "unauthorized" });

    let { method, path, body, action, layout, recordId, fieldData } = req.body || {};

    if (action === "getLayouts") {
      method = "GET";
      path = "/layouts";
    }
    if (action === "getRecord") {
      if (!layout || !recordId) return res.status(400).json({ error: "layout/recordId required" });
      method = "GET";
      path = `/layouts/${layout}/records/${recordId}`;
    }
    if (action === "createRecord") {
      method = "POST";
      path = `/layouts/${layout}/records`;
      body = { fieldData };
    }

    if (!method || !path) return res.status(400).json({ error: "method/path required" });
    method = String(method).toUpperCase();
    if (!ALLOWED_METHODS.has(method)) return res.status(400).json({ error: "method not allowed" });

    if (!path.startsWith("/layouts")) return res.status(400).json({ error: "path must start with /layouts" });
    if (path.includes("?")) return res.status(400).json({ error: "querystring not allowed in path" });

    const token = await getToken();

    const callFM = async (tok) =>
      jsonFetch(`${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${tok}`,
          "Content-Type": "application/json",
        },
        body: method === "GET" ? undefined : JSON.stringify(body || {}),
      });

    let r = await callFM(token);
    if (r.status === 401) {
      cachedToken = null;
      r = await callFM(await getToken());
    }

    res.status(r.status).json(r.json);
  } catch (e) {
    console.error("Error in /fm/request:", e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.listen(PORT, () => console.log(`FM proxy running on port ${PORT}`));