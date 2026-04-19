import "dotenv/config";

async function testGroq() {
  const prompt = `You are a plain-English cybersecurity advisor helping a non-technical business owner understand a security problem with their website or system.

Security Finding Details:
- Issue: Open Port
- Severity: HIGH — This is a critical issue that could cause serious harm if not fixed immediately.
- System Affected: example.com
- Technical Description: Port 443 is open
- Technical Fix: Close it

Respond in exactly this JSON format (raw JSON only, no markdown, no code fences):
{
  "whatIsThis": "Plain English explanation",
  "whyItMatters": "What could realistically happen",
  "howToFix": "Exactly what they should do",
  "analogy": "One sentence analogy"
}`;

  console.log("Sending...");
  const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.GROQ_API_KEY}` },
    body: JSON.stringify({
      model: "llama-3.1-8b-instant",
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert who specialises in explaining complex security issues to non-technical business owners. You always respond with valid raw JSON only — no markdown, no code fences."
        },
        { role: "user", content: prompt }
      ],
      temperature: 0.6,
      max_tokens: 500,
    }),
  });

  console.log("Status:", response.status);
  const data = await response.text();
  console.log("Response:", data);
}

testGroq();
