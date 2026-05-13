export interface ParsedEmail {
  subject?: string;
  sender?: string;
  replyTo?: string;
  bodyText: string;
  rawHeaders?: string;
}

export function cleanEmail(rawEmail: string): ParsedEmail {
  if (!rawEmail || typeof rawEmail !== "string") {
    return { bodyText: "" };
  }

  // 1. Truncate extreme massive inputs immediately to prevent regex catastrophic backtracking/memory limits
  // (We'll slice the first 50k characters for safe processing)
  let processed = rawEmail.slice(0, 50000);

  // 2. Extract Headers (if present) before stripping them for text analysis
  let headersSection = "";
  let bodySection = processed;

  const doubleNewlineIndex =
    processed.indexOf("\n\n") !== -1
      ? processed.indexOf("\n\n")
      : processed.indexOf("\r\n\r\n");

  if (
    doubleNewlineIndex > -1 &&
    doubleNewlineIndex < 10000 &&
    /^(From:|To:|Subject:|Return-Path:|Received:|MIME-Version:)/im.test(
      processed.slice(0, 500),
    )
  ) {
    headersSection = processed.slice(0, doubleNewlineIndex);
    bodySection = processed.slice(doubleNewlineIndex).trim();
  }

  // 3. Extract key details from headers if found
  let subject = "";
  let sender = "";
  let replyTo = "";

  if (headersSection) {
    const subjectMatch = headersSection.match(/^Subject:\s*(.*?)$/im);
    if (subjectMatch) subject = subjectMatch[1].trim();

    const fromMatch = headersSection.match(/^From:\s*(.*?)$/im);
    if (fromMatch) sender = fromMatch[1].trim();

    const replyMatch = headersSection.match(/^Reply-To:\s*(.*?)$/im);
    if (replyMatch) replyTo = replyMatch[1].trim();
  }

  // 4. Strip base64 blocks
  // Base64 blocks in MIME usually follow Content-Transfer-Encoding: base64
  // We can aggressively strip long blocks of contiguous base64 characters
  bodySection = bodySection.replace(
    /(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
    "[BASE64_ATTACHMENT_REMOVED]",
  );

  // Strip CSS / style tags safely
  bodySection = bodySection.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
  // Strip script tags safely
  bodySection = bodySection.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");

  // 5. Remove HTML tags safely but preserve visually separated text
  // Replace opening/closing block div/p/br tags with whitespace so words don't jam together
  bodySection = bodySection.replace(
    /<\/?(?:div|p|br|table|tr|td|h[1-6])[^>]*>/gi,
    " ",
  );
  // Rip all remaining tags
  bodySection = bodySection.replace(/<[^>]+>/g, " ");

  // 6. Normalize Whitespace (replace multiple spaces/newlines with single spaces)
  // Optional: keep newlines for readability but limit consecutive blank lines
  bodySection = bodySection
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ");

  // 7. Decode HTML entities
  bodySection = bodySection
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

  // 8. Truncate final meaningful text completely securely
  bodySection = bodySection.trim().slice(0, 20000);

  return {
    subject,
    sender,
    replyTo,
    bodyText: bodySection,
    rawHeaders: headersSection,
  };
}
