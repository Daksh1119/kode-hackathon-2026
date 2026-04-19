import "dotenv/config";
import express from "express";
import cors from "cors";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Health check
app.get("/api/health", (req, res) => res.send("OK"));

// ── Groq LLM Explain Endpoint ────────────────────────────────────────────
// The API key is securely loaded from your .env file via dotenv.
const GROQ_API_KEY = process.env.GROQ_API_KEY;

app.post("/api/explain", async (req, res) => {
  const { title, description, action, severity, host } = req.body;
  if (!title) return res.status(400).json({ error: "Missing finding title" });

  if (!GROQ_API_KEY) {
    return res.json({
      whatIsThis: description || "No description available.",
      howToFix: action || "No remediation steps available.",
      analogy: "",
      urgencyReason: "",
      source: "fallback",
    });
  }

  const severityContext = {
    HIGH: "This is a critical issue that could cause serious harm if not fixed immediately.",
    MEDIUM: "This is a moderate issue that should be addressed soon.",
    LOW: "This is a low-risk issue but should still be reviewed.",
  }[severity?.toUpperCase()] || "";

  const prompt = `You are a cybersecurity advisor writing a short security alert for a non-technical business owner.

Security Finding Details:
- Issue: ${title}
- Severity: ${severity || "unknown"} — ${severityContext}
- System Affected: ${host || "unknown"}
- Technical Description: ${description || "N/A"}
- Technical Fix: ${action || "N/A"}

Your job: translate this exact issue into literal, everyday English that an office manager with zero IT knowledge can understand.

STRICT RULES:
- NO analogies. NO metaphors. Do NOT use examples like "front door", "shop", "house", or "filing cabinet".
- State precisely what was found on their system in plain text.
- Be factual and calm. Explain exactly what the actual problem is on their specific system.
- The howToFix should tell them exactly who to contact and what to ask them to do.
- Keep each field to 2-3 sentences.

Respond in exactly this JSON format (raw JSON only, no markdown, no code fences):
{
  "whatIsThis": "Plain literal English explanation of the specific security issue without using any analogies.",
  "whyItMatters": "The literal real-world impact to their digital business if they ignore it.",
  "howToFix": "Plain-English actionable steps they can hand to an IT person to solve the exact issue."
}`;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
          {
            role: "system",
            content:
              "You are a cybersecurity expert who translates complex security issues into literal, jargon-free English for business owners. " +
              "You completely avoid all analogies and metaphors. You state facts plainly. " +
              "You always respond with valid raw JSON only — no markdown, no code fences.",
          },
          { role: "user", content: prompt },
        ],
        temperature: 0.6,
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      console.error("Groq API error:", response.status);
      return res.json({ whatIsThis: description, howToFix: action, source: "fallback" });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || "";
    try {
      const cleaned = content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      const parsed = JSON.parse(cleaned);
      return res.json({
        whatIsThis: parsed.whatIsThis || description,
        whyItMatters: parsed.whyItMatters || "",
        howToFix: parsed.howToFix || action,
        analogy: parsed.analogy || "",
        source: "groq",
      });
    } catch (parseErr) {
      return res.json({ whatIsThis: content || description, howToFix: action, source: "groq-raw" });
    }
  } catch (err) {
    console.error("Groq API request failed:", err);
    return res.json({ whatIsThis: description, howToFix: action, source: "fallback" });
  }
});

// ── Groq LLM Remediate Endpoint ────────────────────────────────────────────
app.post("/api/remediate", async (req, res) => {
  const { title, description, host, severity, source: findingSource } = req.body;

  if (!GROQ_API_KEY) {
    return res.json({
      plainEnglishSteps: "Contact your IT team and ask them to review this issue.",
      itBrief: action || "Review and remediate the identified vulnerability.",
      code: "# No API key configured. Cannot generate remediation code.",
      source: "fallback",
    });
  }

  // ── Layer 1 prompt: plain-English action plan for the business owner ──────
  const laymanPrompt = `You are a cybersecurity advisor helping a non-technical business owner take action on a security problem.

Security Problem:
- Issue: ${title || "Unknown"}
- System Affected: ${host || "Unknown"}
- Severity: ${severity || "Unknown"}
- Details: ${description || "N/A"}

Write a plain-English action plan (3-5 numbered steps) for someone with zero IT knowledge.
Each step should say exactly what to DO — who to call, what to ask, what to check.
Use simple everyday language. No jargon. No code. No technical terms.
Example step style: "1. Call your IT support team and tell them: [exact words to say]."

Return ONLY the numbered steps as plain text. No intro, no headings, no markdown.`;

  // ── Layer 2 prompt: terse IT brief + remediation code ─────────────────────
  const techPrompt = `You are a DevOps and Security engineer writing a remediation brief for another engineer.

Vulnerability found:
- Title: ${title || "Unknown"}
- Host: ${host || "Unknown"}
- Severity: ${severity || "Unknown"}
- Details: ${description || "N/A"}
- Source: ${findingSource || "scanner"}

Respond in exactly this JSON format (raw JSON only, no markdown, no code fences):
{
  "itBrief": "One paragraph (3-4 sentences) technical summary of the issue and what the engineer needs to do. Include specific config changes, commands to run, or services to review.",
  "code": "A concise remediation script or config snippet (bash, python, terraform, nginx/apache config, or AWS CLI — whichever is most appropriate). Must be directly runnable. No markdown backticks. No explanations inside the code — use # comments only."
}`;

  try {
    // Run both prompts in parallel for speed
    const [laymanResponse, techResponse] = await Promise.all([
      fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
        body: JSON.stringify({
          model: "llama-3.1-8b-instant",
          messages: [
            {
              role: "system",
              content:
                "You write plain-English action plans for non-technical business owners. " +
                "No jargon, no code, no markdown. Only numbered steps in plain everyday language.",
            },
            { role: "user", content: laymanPrompt },
          ],
          temperature: 0.5,
          max_tokens: 400,
        }),
      }),
      fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
        body: JSON.stringify({
          model: "llama-3.1-8b-instant",
          messages: [
            {
              role: "system",
              content:
                "You are a senior DevOps/Security engineer. " +
                "You output precise technical remediation briefs and runnable code. " +
                "Always respond with valid raw JSON only — no markdown, no code fences wrapping the JSON.",
            },
            { role: "user", content: techPrompt },
          ],
          temperature: 0.2,
          max_tokens: 600,
        }),
      }),
    ]);

    // Parse plain-English steps
    let plainEnglishSteps = "Contact your IT team to review and fix this issue.";
    if (laymanResponse.ok) {
      const laymanData = await laymanResponse.json();
      const laymanText = laymanData.choices?.[0]?.message?.content || "";
      if (laymanText.trim()) plainEnglishSteps = laymanText.trim();
    }

    // Parse IT brief + code
    let itBrief = "Review the vulnerability and apply the appropriate fix.";
    let code = "# Could not generate remediation code.";
    if (techResponse.ok) {
      const techData = await techResponse.json();
      const techContent = techData.choices?.[0]?.message?.content || "";
      try {
        const cleaned = techContent.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
        const parsed = JSON.parse(cleaned);
        itBrief = parsed.itBrief || itBrief;
        // Strip any stray markdown fences the model might have put inside the code field
        code = (parsed.code || code).replace(/```[a-z]*\n?/gi, "").replace(/```\n?/g, "").trim();
      } catch (_) {
        // Model didn't return valid JSON — use raw content as the code block
        code = techContent.replace(/```[a-z]*\n?/gi, "").replace(/```\n?/g, "").trim();
      }
    }

    return res.json({ plainEnglishSteps, itBrief, code, source: "groq" });

  } catch (err) {
    console.error("Groq Remediate error:", err);
    return res.json({
      plainEnglishSteps: "Contact your IT team to review this security issue.",
      itBrief: "Review and remediate the identified vulnerability.",
      code: "# Backend error while generating remediation code.",
      source: "fallback",
    });
  }
});

// The SSE endpoint for running the scan and streaming logs
app.get("/api/scan", (req, res) => {
  const domain = req.query.domain;
  if (!domain || !/^[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+|^[a-zA-Z0-9.-]+$/.test(domain)) {
    return res.status(400).json({ error: "Invalid or missing domain parameter" });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  res.write(`data: ${JSON.stringify({ type: "connected", message: `Connected to scanner backend for ${domain}` })}\n\n`);

  const pythonScriptDir = path.join(__dirname, "..");
  const pythonScriptPath = path.join(pythonScriptDir, "pipeline.py");

  const child = spawn("python", [pythonScriptPath, domain, "--json", "--demo", "--workers", "30"], {
    cwd: pythonScriptDir,
    env: { ...process.env, PYTHONUNBUFFERED: "1", PYTHONIOENCODING: "utf-8" },
  });

  let isClosed = false;

  req.on("close", () => {
    isClosed = true;
    if (!child.killed) {
      console.log("Client disconnected, killing scanner child process...");
      try { child.kill("SIGTERM"); } catch (err) { console.error("Error killing child process:", err); }
    }
  });

  child.on("error", (err) => { console.error("Child process error:", err); });

  child.stdout.on("data", (data) => {
    if (isClosed) return;
    const lines = data.toString().split(/\r?\n/);
    for (const line of lines) {
      if (line.trim().length > 0) {
        const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, "");
        let type = "info";
        if (cleanLine.includes("[ERROR]") || cleanLine.includes("[WARN]")) type = "error";
        if (cleanLine.includes("✔") || cleanLine.includes("complete")) type = "success";
        res.write(`data: ${JSON.stringify({ type, message: cleanLine })}\n\n`);
      }
    }
  });

  child.stderr.on("data", (data) => {
    if (isClosed) return;
    const lines = data.toString().split(/\r?\n/);
    for (const line of lines) {
      if (line.trim().length > 0) {
        const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, "");
        let type = "error";
        if (cleanLine.includes("[INFO]")) type = "info";
        if (cleanLine.includes("[WARN]")) type = "error";
        if (cleanLine.includes("✔") || cleanLine.includes("complete")) type = "success";
        res.write(`data: ${JSON.stringify({ type, message: cleanLine })}\n\n`);
      }
    }
  });

  child.on("close", (code) => {
    if (isClosed) return;
    res.write(`data: ${JSON.stringify({ type: "process_exit", message: `Scan process exited with code ${code}` })}\n\n`);

    const cleanDomain = domain.replace(/\./g, "_");
    const jsonFilePath = path.join(pythonScriptDir, `${cleanDomain}_findings.json`);

    let findings = [];
    if (fs.existsSync(jsonFilePath)) {
      try { findings = JSON.parse(fs.readFileSync(jsonFilePath, "utf-8")); }
      catch (err) { console.error("Failed to parse findings JSON:", err); }
    }

    res.write(`data: ${JSON.stringify({ type: "done", findings })}\n\n`);
    res.end();
  });
});

const PORT = 3001;
app.listen(PORT, () => { console.log(`Backend API running on http://localhost:${PORT}`); });