import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { request as ureq, fetch } from 'undici';

// ⚠️ Tijdelijke fix: accepteer self-signed / verlopen certificaat van FileMaker
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const {
  PORT = 3000,
  API_SECRET,
  FM_HOST,
  FM_DB,
  FM_USER,
  FM_PASS,
  FM_TOKEN_TTL_MIN = 12,
  ALLOW_ORIGIN
} = process.env;

if (!API_SECRET || !FM_HOST || !FM_DB || !FM_USER || !FM_PASS) {
  console.error('Missing env vars');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10mb' }));

// ⭐ CORS – meerdere origins via komma-gescheiden lijst in ALLOW_ORIGIN
app.use(
  cors({
    origin: ALLOW_ORIGIN ? ALLOW_ORIGIN.split(',') : true
  })
);

app.use(morgan('tiny'));

const limiter = new RateLimiterMemory({ points: 60, duration: 60 });
app.use(async (req, res, next) => {
  try {
    await limiter.consume(req.ip);
    next();
  } catch {
    res.status(429).json({ error: 'Too many requests' });
  }
});

let cachedToken = null;
let tokenExp = 0;

// ---------- GENERIEKE FETCH HELPER ----------
async function jsonFetch(url, opts = {}) {
  const r = await ureq(url, opts);
  const t = await r.body.text();

  try {
    return { status: r.statusCode, json: JSON.parse(t) };
  } catch {
    return { status: r.statusCode, json: { raw: t } };
  }
}

// ---------- FILEMAKER TOKEN OPHALEN ----------
async function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExp) return cachedToken;

  const basic = Buffer.from(`${FM_USER}:${FM_PASS}`).toString('base64');

  const { status, json } = await jsonFetch(
    `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/sessions`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'Content-Type': 'application/json'
      },
      body: '{}'
    }
  );

  if (status !== 200 || !json?.response?.token) {
    throw new Error(`FM login failed: ${status} ${JSON.stringify(json)}`);
  }

  cachedToken = json.response.token;
  tokenExp = now + Number(FM_TOKEN_TTL_MIN) * 60 * 1000;
  return cachedToken;
}

// ---------- AUTH HELPER ----------
function okAuth(req) {
  const s = req.header('X-Webhook-Secret');
  const b = req.header('Authorization');
  return (
    (s && s === API_SECRET) ||
    (b && b.startsWith('Bearer ') && b.slice(7) === API_SECRET)
  );
}

// ---------- ROUTES ----------
app.get('/health', (_, res) => res.type('text/plain').send('OK'));

/* 🧪 TEST ROUTE — check outbound connectivity */
app.get('/test', async (req, res) => {
  try {
    const response = await fetch('https://www.google.com');
    const html = await response.text();
    res.status(200).send(
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
app.get('/whois-ip', async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: 'unauthorized' });

    const endpoints = [
      'https://api.ipify.org?format=json',
      'https://ifconfig.me/all.json',
      'https://checkip.amazonaws.com/'
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
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cand)) return res.json({ ip: cand });
        }
      } catch {}
    }

    res.status(502).json({ error: 'could not determine IP' });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🔍 Debiteur zoeken
   Stap 1: zoeken op debiteurNummer + debiteurNaam (veilig; werkt al)
   Stap 2: als er GEEN resultaten zijn, extra poging op adres-velden
           (debiteur_ADRESSEN::Adres / Plaats / Postcode)

   Layout: Debiteur_Rest  (zoals je eerder gebruikte)
*/
app.get('/debiteur/search', async (req, res) => {
  const qRaw = (req.query.q || '').toString();
  const q = qRaw.trim();

  if (!q) {
    return res.status(400).json({ error: 'q (search term) is required' });
  }

  const isNumeric = /^[0-9]+$/.test(q);
  const wildcard = `*${q}*`;

  try {
    const token = await getToken();

    // ---------- 1) BASIS-QUERY: nummer + naam ----------
    const baseQuery = [];

    // exact nummer
    if (isNumeric) {
      baseQuery.push({ debiteurNummer: q });
    }

    // naam bevat q
    baseQuery.push({ debiteurNaam: wildcard });

    const callFind = async (query) =>
      jsonFetch(
        `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Debiteur_Rest/_find`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            query,
            limit: 50
          })
        }
      );

    // Eerst zoeken op nummer/naam
    let { status, json } = await callFind(baseQuery);
    let fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === '0') {
      const records = json?.response?.data || [];
      const mapped = records.map((rec) => ({
        recordId: rec.recordId,
        debiteurNummer: rec.fieldData.debiteurNummer,
        debiteurNaam: rec.fieldData.debiteurNaam,
        telefoon: rec.fieldData.algTelefoon,
        email: rec.fieldData.algEmail
      }));
      return res.json(mapped);
    }

    // Als er GEEN records zijn (401), proberen we adres-zoek
    if (!(status === 200 && fmCode === '401')) {
      // andere FM-error (bijv. 102 veld bestaat niet, 952 auth, etc.)
      console.error(
        'FileMaker error in baseQuery:',
        status,
        JSON.stringify(json)
      );
      return res.status(502).json({ error: 'no matches' });
    }

    // ---------- 2) TWEEDE POGING: alleen adres-velden ----------
    // LET OP: deze veldnamen / TO-naam moeten precies zo in FileMaker staan,
    // anders geeft FileMaker error 102 (unknown field)
    const addressQuery = [
      { 'debiteur_ADRESSEN::Adres': wildcard },
      { 'debiteur_ADRESSEN::Plaats': wildcard },
      { 'debiteur_ADRESSEN::Postcode': wildcard }
    ];

    const second = await callFind(addressQuery);
    status = second.status;
    json = second.json;
    fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === '0') {
      const records = json?.response?.data || [];
      const mapped = records.map((rec) => ({
        recordId: rec.recordId,
        debiteurNummer: rec.fieldData.debiteurNummer,
        debiteurNaam: rec.fieldData.debiteurNaam,
        telefoon: rec.fieldData.algTelefoon,
        email: rec.fieldData.algEmail
      }));
      return res.json(mapped);
    }

    if (status === 200 && fmCode === '401') {
      // ook op adres niets gevonden
      return res.json({ error: 'no matches' });
    }

    console.error(
      'FileMaker error in addressQuery:',
      status,
      JSON.stringify(json)
    );
    return res.json({ error: 'no matches' });
  } catch (err) {
    console.error('Error in /debiteur/search:', err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

/* 🔍 Servicebon zoeken (Servicebon_Rest)
   Zoekt op:
   - projectcode
   - projectNaam
   - PROJECT::debiteurNaam / debiteurNummer
   - project_SERVICECONTRACTEN::contractCode / contractNummer
   - project_SERVICECONTRACTEN::machine / machineType

   Let op:
   - Op dit moment krijg je in fieldData '<No Access>' totdat de FM-rechten
     voor account 'restuser' op layout Servicebon_Rest goed staan.
*/
app.get('/servicebon/search', async (req, res) => {
  const qRaw = (req.query.q || '').toString();
  const q = qRaw.trim();

  if (!q) {
    return res.status(400).json({ error: 'q (search term) is required' });
  }

  const wildcard = `*${q}*`;

  try {
    const token = await getToken();

    const fmQuery = [];

    // Zo breed mogelijk zoeken op relevante velden
    fmQuery.push(
      { projectcode: wildcard },
      { projectNaam: wildcard },
      { 'PROJECT::debiteurNaam': wildcard },
      { 'PROJECT::debiteurNummer': wildcard },
      { 'project_SERVICECONTRACTEN::contractCode': wildcard },
      { 'project_SERVICECONTRACTEN::contractNummer': wildcard },
      { 'project_SERVICECONTRACTEN::contractType': wildcard },
      { 'project_SERVICECONTRACTEN::machine': wildcard },
      { 'project_SERVICECONTRACTEN::machineType': wildcard }
    );

    const { status, json } = await jsonFetch(
      `${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}/layouts/Servicebon_Rest/_find`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: fmQuery,
          limit: 50
        })
      }
    );

    const fmCode = json?.messages?.[0]?.code;

    if (status === 200 && fmCode === '0') {
      const records = json?.response?.data || [];
      const mapped = records.map((rec) => {
        const f = rec.fieldData || {};
        return {
          recordId: rec.recordId,
          projectcode: f.projectcode,
          projectNaam: f.projectNaam,
          debiteurNummer: f['PROJECT::debiteurNummer'],
          debiteurNaam: f['PROJECT::debiteurNaam'],
          debiteurTelefoon: f['project_DEBITEUR::algTelefoon'],
          debiteurEmail: f['project_DEBITEUR::algEmail'],
          contractCode: f['project_SERVICECONTRACTEN::contractCode'],
          contractNummer: f['project_SERVICECONTRACTEN::contractNummer'],
          contractType: f['project_SERVICECONTRACTEN::contractType'],
          machine: f['project_SERVICECONTRACTEN::machine'],
          machineType: f['project_SERVICECONTRACTEN::machineType']
        };
      });
      return res.json(mapped);
    }

    if (status === 200 && fmCode === '401') {
      return res.json({ error: 'no matches' });
    }

    console.error(
      'FileMaker find error in /servicebon/search:',
      status,
      JSON.stringify(json)
    );
    return res.status(502).json({ error: 'FileMaker response error' });
  } catch (err) {
    console.error('Error in /servicebon/search:', err);
    return res.status(500).json({ error: String(err.message || err) });
  }
});

// ---------- HOOFDENDPOINT /fm/request ----------
app.post('/fm/request', async (req, res) => {
  try {
    if (!okAuth(req)) return res.status(401).json({ error: 'unauthorized' });

    let { method, path, body, action, layout, recordId, fieldData } =
      req.body || {};

    if (action === 'getLayouts') {
      method = 'GET';
      path = '/layouts';
    }
    if (action === 'getRecord') {
      if (!layout || !recordId)
        return res.status(400).json({ error: 'layout/recordId required' });
      method = 'GET';
      path = `/layouts/${layout}/records/${recordId}`;
    }
    if (action === 'createRecord') {
      method = 'POST';
      path = `/layouts/${layout}/records`;
      body = { fieldData };
    }

    if (!method || !path)
      return res.status(400).json({ error: 'method/path required' });

    if (!path.startsWith('/layouts'))
      return res.status(400).json({ error: 'path must start with /layouts' });

    const token = await getToken();

    const callFM = async (tok) =>
      jsonFetch(`${FM_HOST}/fmi/data/vLatest/databases/${FM_DB}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${tok}`,
          'Content-Type': 'application/json'
        },
        body: method === 'GET' ? undefined : JSON.stringify(body || {})
      });

    let r = await callFM(token);
    if (r.status === 401) {
      cachedToken = null;
      r = await callFM(await getToken());
    }

    res.status(r.status).json(r.json);
  } catch (e) {
    console.error('Error in /fm/request:', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.listen(PORT, () =>
  console.log(`FM proxy running on port ${PORT}`)
);
