const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());

app.get("/", (req, res) => {
  res.send("✅ Malicious URL Scanner API is running. Use /scan?url=https://example.com");
});

app.get("/scan", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: "Missing URL parameter" });

  const results = {};
  const limitMessages = [];
  const usage = {
    safeBrowsing: "N/A",
    virusTotal: "N/A"
  };

  try {
    const safeResp = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
      {
        client: { clientId: "layerbit", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }
    );
    results["Google Safe Browsing"] = safeResp.data && safeResp.data.matches
      ? "❌ Threat Detected"
      : "✅ Clean";
    usage.safeBrowsing = "10,000/day";
  } catch (e) {
    results["Google Safe Browsing"] = "⚠️ API Error";
    limitMessages.push("Safe Browsing quota or key issue.");
  }

  try {
    const encodedUrl = Buffer.from(url).toString("base64").replace(/=+$/, "");
    const vtResp = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
    });
    const stats = vtResp.data.data.attributes.last_analysis_stats;
    results["VirusTotal"] = stats.malicious > 0
      ? `⚠️ ${stats.malicious} flagged`
      : "✅ Clean";
    usage.virusTotal = "500/day";
  } catch (e) {
    results["VirusTotal"] = "⚠️ API Error";
    limitMessages.push("VirusTotal quota or key issue.");
  }

  res.json({ results, usage, limitReached: limitMessages.length > 0, limitMessages });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🎯 SERVER READY at http://localhost:${PORT}`);
});