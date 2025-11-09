import { fetch } from "undici";

const url = "https://www.google.com";

try {
  const res = await fetch(url);
  console.log(`✅ Connected! Status: ${res.status}`);
} catch (err) {
  console.error("❌ Connection failed:", err.message);
}
