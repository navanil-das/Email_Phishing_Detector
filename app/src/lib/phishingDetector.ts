// Phishing detection via ML API (URL) + heuristics (email)
export type DetectionResult = {
  isSafe: boolean;
  score: number; // 0-100, higher = more suspicious
  reasons: string[];
  type: "url" | "email";
  input: string;
};

// ---- CONFIG ----
// Put your deployed FastAPI URL here
const API_URL = import.meta.env.VITE_PREDICT_API_URL;

// ---- URL helpers ----
function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

// ---- ML-backed URL detection ----
export async function detectURL(url: string): Promise<DetectionResult> {
  const normalized = normalizeUrl(url);

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: normalized }),
    });

    if (!res.ok) {
      throw new Error(`API error: ${res.status}`);
    }

    const data: { url: string; phishing: "Yes" | "No" } = await res.json();
    const isPhishing = data.phishing === "Yes";

    return {
      isSafe: !isPhishing,
      score: isPhishing ? 85 : 10,
      reasons: isPhishing
        ? [
            "ML model classified this URL as phishing based on URL structure and website signals",
          ]
        : ["ML model found no strong phishing indicators for this URL"],
      type: "url",
      input: url,
    };
  } catch (err) {
    console.error("URL detection failed, falling back:", err);

    // Conservative fallback if API is unreachable
    return {
      isSafe: false,
      score: 60,
      reasons: [
        "Phishing detection service is currently unavailable. Treat this link with caution.",
      ],
      type: "url",
      input: url,
    };
  }
}

// ---------------- EMAIL HEURISTICS (UNCHANGED) ----------------

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"];

const LEGITIMATE_DOMAINS = [
  "google.com", "gmail.com", "youtube.com", "facebook.com",
  "twitter.com", "instagram.com", "linkedin.com", "github.com",
  "microsoft.com", "apple.com", "amazon.com", "netflix.com",
  "spotify.com", "paypal.com", "wikipedia.org", "reddit.com",
  "stackoverflow.com", "w3schools.com", "mdn.mozilla.org",
  "lovable.dev", "vercel.com", "netlify.com",
];

const PHISHING_EMAIL_PATTERNS = [
  /noreply@.*\.(tk|ml|ga|cf|gq)/i,
  /support@.*free\.com/i,
  /security.*alert@/i,
  /account.*verify@/i,
  /urgent.*action@/i,
];

const SUSPICIOUS_EMAIL_DOMAINS = [
  "tempmail.com", "throwaway.email", "mailinator.com",
  "guerrillamail.com", "yopmail.com", "trashmail.com",
  "sharklasers.com", "guerrillamailblock.com",
];

export function detectEmail(email: string): DetectionResult {
  const reasons: string[] = [];
  let score = 0;

  const lowerEmail = email.toLowerCase().trim();
  const parts = lowerEmail.split("@");

  if (parts.length !== 2) {
    return {
      isSafe: false,
      score: 90,
      reasons: ["Invalid email format"],
      type: "email",
      input: email,
    };
  }

  const [localPart, emailDomain] = parts;

  if (SUSPICIOUS_EMAIL_DOMAINS.includes(emailDomain)) {
    score += 50;
    reasons.push("Email uses a known disposable/temporary mail service");
  }

  PHISHING_EMAIL_PATTERNS.forEach((pattern) => {
    if (pattern.test(lowerEmail)) {
      score += 35;
      reasons.push("Email matches known phishing address pattern");
    }
  });

  if (SUSPICIOUS_TLDS.some((tld) => emailDomain.endsWith(tld))) {
    score += 30;
    reasons.push("Email domain uses a high-risk TLD");
  }

  if ((localPart.includes("noreply") || localPart.includes("no-reply")) &&
      !LEGITIMATE_DOMAINS.includes(emailDomain)) {
    score += 15;
    reasons.push("No-reply sender from an unrecognized domain");
  }

  if (/[0-9]/.test(emailDomain.split(".")[0]) && emailDomain.split(".")[0].length < 8) {
    score += 20;
    reasons.push("Domain uses numbers to impersonate letters (typosquatting)");
  }

  if (localPart.length > 40) {
    score += 10;
    reasons.push("Unusually long email local part");
  }

  if (LEGITIMATE_DOMAINS.some((d) => emailDomain === d)) {
    score = Math.max(0, score - 20);
    reasons.push("Email domain belongs to a recognized provider");
  }

  const cappedScore = Math.min(score, 100);

  if (reasons.length === 0) {
    reasons.push("No obvious phishing indicators found");
  }

  return {
    isSafe: cappedScore < 40,
    score: cappedScore,
    reasons,
    type: "email",
    input: email,
  };
}

// ---------------- MAIN ANALYZER ----------------

export async function analyze(input: string): Promise<DetectionResult> {
  const trimmed = input.trim();

  // Email
  if (trimmed.includes("@") && !trimmed.startsWith("http") && !trimmed.startsWith("www")) {
    return detectEmail(trimmed);
  }

  // URL (ML API)
  return detectURL(trimmed);
}
