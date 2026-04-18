/**
 * Intent analysis for the detector.
 *
 * The useful question here is not just "what words are present?"
 * but "what is the sender pushing the user to do?"
 *
 * That distinction mattered a lot once we started testing short scams
 * and no-link BEC messages.
 */

export type IntentType = "SAFE" | "ACTION_REQUIRED" | "DANGEROUS";

export interface IntentResult {
  intentType: IntentType;
  isUserAskedToAct: boolean;
  isSensitiveRequest: boolean;
  isInformational: boolean;
  hasAccountAlert: boolean;
  hasFinancialDemand: boolean;
  hasUrgencyPressure: boolean;
  hasAuthorityImpersonation: boolean;
  hasCredentialRequest: boolean;
  intentRiskScore: number;
  matchedIntentSignals: string[];
  actionVerbs: string[];
  sensitiveTerms: string[];
  safeContextPhrases: string[];
}

// Strip our own explainer boilerplate first; otherwise repeated scans can pollute the next result.
const PHISHSHIELD_BOILERPLATE =
  /what to do next.*?call the official helpline[^\n]*/gis;

// Safe disclaimer phrases — stripped before checking action words
const SAFE_DISCLAIMERS =
  /do not share|don'?t share|never share|will never ask|won'?t ask|ignore if not you|ignore this email|if this was not you|if not you|we will never|customer care will never|service will never|do not click|never disclose|never ask for|you requested to sign in|someone else might have typed|you received this email because|किसी के साथ साझा न करें|साझा न करें|मत साझा करें|share mat karo|share मत करें|कोई (?:कार्रवाई|action) (?:required|आवश्यक) नहीं है|koi action required nahi hai|agar ye aap the|agar ye aap nahi the/gi;

// Dangerous actions — commands to export/reveal data (Direct extraction)
const DANGEROUS_ACTION_PATTERNS = [
  { pattern: /\bsend(?:ing)?\s+(?:your|the|us|it)\b/i, verb: "send" },
  { pattern: /\bsend(?:ing)?\b/i, verb: "send" },
  { pattern: /\breply(?:ing)?\s+(?:with|to)\b/i, verb: "reply" },
  { pattern: /\breply(?:ing)?\b/i, verb: "reply" },
  { pattern: /\bshare(?:ing)?\b/i, verb: "share" },
  { pattern: /\bprovid(?:e|ing)\b/i, verb: "provide" },
  { pattern: /\benter(?:ing)?\s+(?:your|the)\b/i, verb: "enter" },
  { pattern: /\bsubmit(?:ting)?\s+(?:your|the)\b/i, verb: "submit" },
  { pattern: /\bconfirm(?:ing)?\s+(?:your|the|identity|account|payment|transfer)\b/i, verb: "confirm" },
  { pattern: /\bverify(?:ing)?\s+(?:your|the|identity|account|now|immediately)\b/i, verb: "verify" },
  { pattern: /\bupdate(?:ing)?\s+(?:your|the|account|information|details)\b/i, verb: "update" },
  { pattern: /\breset(?:ting)?\s+(?:your\s+)?(?:password|credentials|login)\b/i, verb: "reset" },
  { pattern: /\bsecure(?:ing)?\s+(?:your\s+)?(?:account|login)\b/i, verb: "secure" },
  { pattern: /\bunlock(?:ing)?\s+(?:your\s+)?account\b/i, verb: "unlock" },
  { pattern: /\btransfer(?:ring)?\s+(?:funds?|money|payment)\b/i, verb: "transfer" },
  { pattern: /\b(?:approve|process)(?:ing)?\s+(?:the\s+)?(?:payment|invoice|transfer)\b/i, verb: "approve payment" },
  // Hindi/Hinglish data export verbs
  { pattern: /\b(?:bhej|bhejna|bhejo|bhejdo|bhej\s+de|bhej\s+dena|batao|batana|bataiye|bataye)\b/i, verb: "send" },
  { pattern: /\bshare\s+kar(?:ein|o|iye|na)\b/i, verb: "share" },
];

// Suspicious/Required actions — commands to navigate or perform a task
const SUSPICIOUS_ACTION_PATTERNS = [
  { pattern: /\bshar(?:e|ing)?\s+(?:your|the)\b/i, verb: "share" },
  { pattern: /\bshare\s+kar(?:ein|o|iye|na)\b/i, verb: "share" },
  { pattern: /\bprovid(?:e|ing)\s+(?:your|the)\b/i, verb: "provide" },
  { pattern: /\bclick(?:ing)?\s+(?:here|below|this|the)\b/i, verb: "click" },
  { pattern: /\blog(?:ging)?\s*-?\s*in\b/i, verb: "login" },
  { pattern: /\bsign(?:ing)?\s*-?\s*in\b/i, verb: "login" },
  { pattern: /\bvisit(?:ing)?\s+(?:the|our)\b/i, verb: "visit" },
  { pattern: /\bgo\s+to\s+(?:the|our)\b/i, verb: "visit" },
  { pattern: /\bopen\s+(?:https?:\/\/|www\.|[^\s]+\.[a-z]{2,})/i, verb: "open link" },
  { pattern: /\bcall(?:ing)?\s+(?:us|our|this)\b/i, verb: "call" },
  { pattern: /\bverify(?:ing)?\s+(?:now|your|account|immediately)\b/i, verb: "verify" },
  { pattern: /\bupdate(?:ing)?\s+(?:now|your|account|information|details|immediately)\b/i, verb: "update" },
  { pattern: /\bconfirm(?:ing)?\s+(?:now|your|identity|account|payment|transfer)\b/i, verb: "confirm" },
  { pattern: /\benter(?:ing)?\s+(?:your|the)\b/i, verb: "enter" },
  { pattern: /\bforward(?:ing)?\s+(?:this|your)\b/i, verb: "forward" },
  { pattern: /\bpay(?:ing)?\b/i, verb: "pay" },
  { pattern: /\bdeposit(?:ing)?\b/i, verb: "deposit" },
  { pattern: /\btransfer(?:ring)?\s+(?:funds?|money|payment)\b/i, verb: "transfer" },
  { pattern: /\b(?:approve|process)(?:ing)?\s+(?:the\s+)?(?:payment|invoice|transfer)\b/i, verb: "approve payment" },
  { pattern: /\b(?:handle|complet(?:e|ing)|process(?:ing)?|finish|sort|take\s+care\s+of)\s+(?:this|it|the)\s+(?:task|request|item|payment|invoice|transfer)?\b/i, verb: "complete task" },
  { pattern: /\bdo\s+(?:this|it)\b/i, verb: "complete task" },
  { pattern: /\b(?:send\s+confirmation|confirm\s+once\s+done)\b/i, verb: "complete task" },
  { pattern: /\b(?:jaldi\s+karo|verify\s+karo|confirm\s+karo|payment\s+karo|otp\s+bhejo?)\b/i, verb: "complete task" },
  { pattern: /\bact\s+now\b/i, verb: "act now" },
  { pattern: /\bscan\s+(?:the\s+)?qr\s+code\b/i, verb: "scan qr" },
  { pattern: /\bapprove\s+(?:the\s+)?(?:request|prompt|push|notification|sign(?:-|\s)?in|login)\b/i, verb: "approve" },
  { pattern: /\btap\s+(?:approve|yes)\b/i, verb: "approve" },
  { pattern: /\bauthori[sz]e\s+(?:the\s+)?(?:app|request|sign(?:-|\s)?in|login)\b/i, verb: "authorize" },
  { pattern: /\bgrant\s+consent\b/i, verb: "consent" },
  { pattern: /\bconnect\s+(?:your\s+)?wallet\b/i, verb: "connect wallet" },
  { pattern: /\bopen\s+(?:microsoft\s+authenticator|authenticator(?:\s+app)?|the\s+attached\s+(?:svg\s+)?(?:voice|voicemail|audio)\s+(?:message|recording)|the\s+(?:svg\s+)?(?:voice|voicemail|audio)\s+(?:message|recording)|the\s+attachment)\b/i, verb: "open attachment" },
  { pattern: /\bdownload\s+(?:the\s+)?(?:attachment|file)\b/i, verb: "download" },
  { pattern: /\bview\s+(?:the\s+)?(?:document|file)\b/i, verb: "view document" },
  { pattern: /\breview\s+(?:the\s+)?document\b/i, verb: "review document" },
  { pattern: /\breset(?:ting)?\s+(?:your\s+)?(?:password|credentials|login)\b/i, verb: "reset" },
  { pattern: /\bsecure(?:ing)?\s+(?:your\s+)?(?:account|login)\b/i, verb: "secure" },
  { pattern: /\bunlock(?:ing)?\s+(?:your\s+)?account\b/i, verb: "unlock" },
  { pattern: /\bcontinue\b|\bproceed\b/i, verb: "continue" },
  { pattern: /\bcheck(?:ing)?\s+(?:your\s+)?(?:account|status)\b/i, verb: "check" },
  { pattern: /\breview(?:ing)?\s+(?:your\s+)?(?:account|information|security settings)\b/i, verb: "review" },
  { pattern: /\bclick(?:ing)?\s+(?:the\s+)?link\b/i, verb: "click" },
];

// Sensitive data terms — things an attacker wants
const SENSITIVE_TERMS = [
  { pattern: /\botp\b/i, term: "OTP" },
  { pattern: /\bpassword\b/i, term: "password" },
  { pattern: /\bpin\b/i, term: "PIN" },
  { pattern: /\baadhaar\b/i, term: "Aadhaar" },
  { pattern: /\bcredentials?\b/i, term: "credentials" },
  { pattern: /\bcvv\b/i, term: "CVV" },
  { pattern: /\bcard\s*number\b/i, term: "card number" },
  { pattern: /\baccount\s*number\b/i, term: "account number" },
  { pattern: /\bbank\s*details?\b/gi, term: "bank details" },
  { pattern: /\bcard\s*details?\b/gi, term: "card details" },
  { pattern: /\bbilling\s*details?\b/gi, term: "billing details" },
  { pattern: /\bemail\s*address\b/gi, term: "email address" },
  { pattern: /\blog(?:-|\s)?in\s*details?\b/gi, term: "login details" },
  { pattern: /\bsign(?:-|\s)?in\s*details?\b/gi, term: "sign-in details" },
  { pattern: /\bidentity\s*(?:information|details?|documents?)\b/gi, term: "identity information" },
  { pattern: /\bmailbox\s*(?:credentials|ownership)\b/gi, term: "mailbox credentials" },
  { pattern: /\b(?:account|profile)\s*(?:info|information|details?|records?)\b/gi, term: "account info" },
  { pattern: /\bsocial\s*security\b/gi, term: "SSN" },
  { pattern: /\bpan\s+(?:card|number)\b/gi, term: "PAN" },
  { pattern: /seed\s*phrase|recovery\s*phrase/i, term: "seed phrase" },
  { pattern: /private\s*key|wallet\s*key|passphrase/i, term: "private key" },
  { pattern: /session\s*token|cookie\s*token|backup\s*code/i, term: "session token" },
  { pattern: /salary\s*account|beneficiary/i, term: "beneficiary" },
];

// Safe context phrases — signs the email is informational
const SAFE_CONTEXT_PATTERNS = [
  { pattern: /do not share/i, phrase: "do not share" },
  { pattern: /never share/i, phrase: "never share" },
  { pattern: /don'?t share/i, phrase: "don't share" },
  { pattern: /किसी के साथ साझा न करें|साझा न करें|मत साझा करें|share mat karo|share मत करें/i, phrase: "do not share" },
  { pattern: /will never ask/i, phrase: "will never ask" },
  { pattern: /ignore if not you/i, phrase: "ignore if not you" },
  { pattern: /ignore this email/i, phrase: "ignore this email" },
  { pattern: /if this was not you/i, phrase: "if this was not you" },
  { pattern: /अगर (?:यह|ये) आप नहीं थे|agar ye aap nahi the/i, phrase: "if this was not you" },
  { pattern: /if this was you|agar ye aap the/i, phrase: "if this was you" },
  { pattern: /no action required|कोई (?:कार्रवाई|action) (?:required|आवश्यक) नहीं है|koi action required nahi hai/i, phrase: "no action required" },
  { pattern: /official app|official website|आधिकारिक (?:app|ऐप|site|website)|official app me review|official app se review/i, phrase: "official app" },
  { pattern: /this is (?:an? )?automated/i, phrase: "automated message" },
  { pattern: /do not reply/i, phrase: "do not reply" },
  { pattern: /you requested to sign in/i, phrase: "requested sign-in" },
  { pattern: /you received this email because/i, phrase: "standard notification" },
  { pattern: /meeting invitation|join zoom meeting|meeting id|calendar invite|passcode:\s*\d+|join (?:the )?meeting/i, phrase: "meeting invite" },
  { pattern: /view completed document in docusign|completed: .*signed/i, phrase: "completed document notice" },
  { pattern: /unsubscribe|privacy\s*[·•|]\s*terms|official blog|release notes|newsletter|product update|logging and training policies|data retention|zero data retention|privacy dashboard/i, phrase: "newsletter footer" },
  { pattern: /you(?:'ve|'ve| have) successfully (?:subscribed|signed up|registered|created)/i, phrase: "confirmation" },
  { pattern: /subscription will (?:automatically )?renew/i, phrase: "subscription notice" },
  { pattern: /you can cancel at any time/i, phrase: "cancel anytime" },
  { pattern: /order (?:number|confirmation|placed|shipped)/i, phrase: "order confirmation" },
];

const FINANCIAL_DEMAND_PATTERNS = [
  /\bpay(?:ment)?\b|\btransfer\b|wire transfer|bank transfer|invoice|\bfee\b|deposit|beneficiary|money|funds?|refund|billing|card details|payment failed/i,
  /₹|\brs\.?\b|rupees|cashback|reward|wallet|btc|bitcoin|crypto|income tax|tax notice|penalty|pan|aadhaar/i,
];

const URGENCY_PRESSURE_PATTERNS = [
  /urgent|urgently|immediate(?:ly)?|right away|right now|act now|final notice|within \d+ hours?|24h|24 hours|asap|required|avoid (?:closure|suspension|disruption|penalty|action)|under review|quickly|very important|important update|account (?:will be )?closed|closed in 24h|disabled|restriction|restricted|terminated|maintain access|restore access|before noon|tonight/i,
  /jaldi|abhi|turant|warna|nahi toh|block ho jayega|band ho jayega|band hone wala hai|service ruk jayegi|khata band|issue hoga|problem hogi|తక్షణం|వెంటనే|तुरंत|अभी|जल्दी/i,
];

const AUTHORITY_IMPERSONATION_PATTERNS = [
  /boss|ceo|cfo|finance team|hr|payroll|manager/i,
  /bank|support|helpdesk|security team|dear customer|dear user|dear account holder|income tax|government|tax department/i,
];

const CREDENTIAL_REQUEST_PATTERNS = [
  /\botp\b|password|pin\b|passcode|cvv|credentials?|verify|confirm|authenticate|reset|secure/i,
  /account details|account info|bank details|billing details|card details|email address|aadhaar|pan|identity|security code/i,
];

export function analyzeIntent(emailText: string): IntentResult {
  // 0. Strip PhishShield's own boilerplate to prevent self-contamination
  const cleanedText = emailText.replace(PHISHSHIELD_BOILERPLATE, " ");

  // 1. Remove zero-width obfuscation characters
  const deObfuscatedText = cleanedText.replace(/[\u200B-\u200D\uFEFF]/g, "");

  // 2. Normalize whitespace
  const textLower = deObfuscatedText.toLowerCase().replace(/\s+/g, " ");
  const contentOnlyText = textLower
    .replace(/(?:from|reply-to|return-path|subject):[^\n]+/gi, " ")
    .replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g, " ")
    .replace(/\s+/g, " ");

  // Sanitize text: remove disclaimers that contain keywords like 'OTP', 'PIN', etc.
  const sanitizedText = contentOnlyText.replace(SAFE_DISCLAIMERS, " __SAFE__ ");

  // Detect action verbs (on sanitized text)
  const dangerousVerbs: string[] = [];
  for (const { pattern, verb } of DANGEROUS_ACTION_PATTERNS) {
    if (pattern.test(sanitizedText)) dangerousVerbs.push(verb);
  }

  const suspiciousVerbs: string[] = [];
  for (const { pattern, verb } of SUSPICIOUS_ACTION_PATTERNS) {
    if (pattern.test(sanitizedText)) suspiciousVerbs.push(verb);
  }

  // Detect sensitive terms (on SANITIZED text — so disclaimers don't pollute)
  const sensitiveTerms: string[] = [];
  for (const { pattern, term } of SENSITIVE_TERMS) {
    if (pattern.test(sanitizedText)) {
      sensitiveTerms.push(term);
    }
  }

  // --- ANTI-EVASION: Detect truly spaced-out words ---
  // Only trigger if the word exists in despaced form but NOT as a normal word in original text
  // This catches "p a s s w o r d" but NOT "password" in normal sentences
  const words = textLower.split(/\s+/);
  const normalWordsSet = new Set(words);

  // Check for spaced-out evasion: if single characters appear in sequence that form a keyword
  const checkSpacedEvasion = (keyword: string): boolean => {
    // Look for the keyword's characters appearing as individual letters separated by spaces
    // e.g., "p a s s w o r d" → individual chars in sequence
    const spacedPattern = keyword.split("").join("\\s+");
    const spacedRegex = new RegExp(spacedPattern, "i");
    return spacedRegex.test(textLower) && !normalWordsSet.has(keyword);
  };

  if (checkSpacedEvasion("password") && !sensitiveTerms.includes("password")) {
    sensitiveTerms.push("password");
  }
  if (checkSpacedEvasion("otp") && !sensitiveTerms.includes("OTP")) {
    sensitiveTerms.push("OTP");
  }
  if (checkSpacedEvasion("share") && !suspiciousVerbs.includes("share")) {
    suspiciousVerbs.push("share");
  }
  if (checkSpacedEvasion("send") && !dangerousVerbs.includes("send")) {
    dangerousVerbs.push("send");
  }

  // Compile final merged lists
  const actionVerbs = [...dangerousVerbs, ...suspiciousVerbs].filter(Boolean);

  // Detect safe context phrases (on original text)
  const safeContextPhrases: string[] = [];
  for (const { pattern, phrase } of SAFE_CONTEXT_PATTERNS) {
    if (pattern.test(textLower)) {
      safeContextPhrases.push(phrase);
    }
  }

  const isUserAskedToAct = actionVerbs.length > 0;
  const hasFinancialDemand = FINANCIAL_DEMAND_PATTERNS.some((pattern) => pattern.test(sanitizedText));
  const hasUrgencyPressure = URGENCY_PRESSURE_PATTERNS.some((pattern) => pattern.test(sanitizedText));
  const hasAuthorityImpersonation = AUTHORITY_IMPERSONATION_PATTERNS.some((pattern) => pattern.test(sanitizedText));
  const hasNoClearSafeContext = safeContextPhrases.length === 0;
  const hasVagueTaskLanguage =
    /\b(?:handle|complete|process|finish|sort|take\s+care\s+of)\s+(?:this|it|the)\s+(?:task|request|item|payment|invoice|transfer)?\b/i.test(sanitizedText) ||
    /\bdo\s+(?:this|it)\b/i.test(sanitizedText) ||
    /\b(?:send\s+confirmation|confirm\s+once\s+done|jaldi\s+karo|verify\s+karo|confirm\s+karo|payment\s+karo)\b/i.test(sanitizedText);
  const hasBecStyleTaskPressure = hasVagueTaskLanguage && hasUrgencyPressure && hasNoClearSafeContext;
  const hasHighSensitivityTerm = sensitiveTerms.some((term) =>
    [
      "OTP",
      "password",
      "PIN",
      "Aadhaar",
      "credentials",
      "CVV",
      "card number",
      "account number",
      "bank details",
      "card details",
      "billing details",
      "login details",
      "sign-in details",
      "identity information",
      "mailbox credentials",
      "PAN",
      "seed phrase",
      "private key",
      "session token",
      "beneficiary",
    ].includes(term),
  );
  const hasMfaApprovalLure =
    /(microsoft\s+authenticator|authenticator(?:\s+app)?|approval\s+request|pending\s+sign(?:-|\s)?in|sign(?:-|\s)?in\s+request|push\s+notification|okta)/i.test(
      sanitizedText,
    ) &&
    /(approve|accept|confirm|authorize|tap\s+(?:approve|yes))/i.test(sanitizedText) &&
    /(request|mailbox|email|inbox|access|login|sign(?:-|\s)?in)/i.test(sanitizedText);
  const hasVoiceMessageSigninLure =
    /(svg|voice(?:mail)?|voice\s+message|audio\s+message|recording)/i.test(sanitizedText) &&
    /(open|download|view|hear|listen|play)/i.test(sanitizedText) &&
    /(sign(?:-|\s)?in|log(?:-|\s)?in|authenticate|access)/i.test(sanitizedText);
  const hasBenignMeetingInvite =
    /(meeting invitation|join zoom meeting|meeting id|calendar invite|join (?:the )?meeting)/i.test(textLower) &&
    /passcode[:\s]*\d+/i.test(textLower) &&
    !/(confirm your (?:identity|credentials|login details)|verify your identity|keep access|maintain access|re-?enter|secure thread|update account)/i.test(textLower);
  const hasPasscodeOnlyContext =
    /\bpasscode\b/i.test(sanitizedText) &&
    !/\botp\b|password|pin\b|credentials?|login details|sign(?:-|\s)?in details?|identity (?:information|details?|documents?)/i.test(
      sanitizedText,
    );
  const hasCredentialRequest =
    !((hasBenignMeetingInvite && hasPasscodeOnlyContext)) &&
    (
      hasHighSensitivityTerm ||
      hasMfaApprovalLure ||
      hasVoiceMessageSigninLure ||
      /\botp\b|password|pin\b|passcode|cvv|credentials?|login details|bank details|billing details|card details|aadhaar|pan\b|beneficiary|wallet details?|private key|seed phrase|sign(?:-|\s)?in details?|identity (?:information|details?|documents?)|mailbox (?:credentials|ownership|access)|approve (?:the )?(?:request|sign(?:-|\s)?in|login)/i.test(
        sanitizedText,
      )
    );

  const hasCredentialHarvestAction =
    dangerousVerbs.length > 0 ||
    suspiciousVerbs.some((verb) => ["login", "approve", "authorize", "open attachment", "open link", "download", "click"].includes(verb));

  // isSensitiveRequest = credential lure paired with an action that harvests access or approval
  const isSensitiveRequest = hasCredentialRequest && hasCredentialHarvestAction;
  const isInformational = safeContextPhrases.length > 0;

  // Specific check for account verification alerts — must NOT trigger on subscription/order receipts
  const isSubscriptionReceipt =
    /subscri(?:bed|ption|be)|order (?:number|confirmation|placed)|invoice(?: for your purchase)?|receipt|payment successful|invoice paid|order has been shipped|tracking details|shipment (?:is )?dispatched/i.test(
      textLower,
    );
  const hasCoreActionVerb =
    /\b(?:verify|update|confirm|review|check|process|submit|handle|complete|transfer|finish|sort|secure|reset|take action|ensure|maintain|login|approve|authorize|open)\b/i.test(
      textLower,
    );
  const hasActionContextCombo =
    hasCoreActionVerb &&
    /(account|profile|payment|invoice|service|payroll|bank|security|details?|information|activity|login|identity|documents?|status|access)/i.test(
      textLower,
    );
  const hasEscalatingConsequence =
    /urgent|urgently|immediate(?:ly)?|asap|today|next hour|time sensitive|24h|24 hours|(?:in|within) (?:the )?(?:next )?\d+\s*(?:hours?|hr)|avoid (?:closure|suspension|disruption|penalty|action)|account (?:will be )?closed|closed in 24h|blocked|suspended|lockout|locked\s*out|maintain\s+(?:\w+\s+){0,2}access|restore\s+(?:\w+\s+){0,2}access|keep\s+(?:\w+\s+){0,2}access|ensure uninterrupted service|service disruption|payroll closes|quickly|very important|jaldi|warna|band ho jayega|block ho jayega|band hone wala hai|khata band|issue hoga|problem hogi|వెంటనే|తక్షణం|तुरंत/i.test(
      textLower,
    );
  const hasGenericAccountMaintenance =
    hasActionContextCombo &&
    /(continue|service|access|security|details|information|review|attention|status|activity)/i.test(
      textLower,
    );
  const hasAccountAlert =
    !isSubscriptionReceipt &&
    (hasGenericAccountMaintenance ||
      (/verify|check|review/i.test(textLower) && /account|activity|login/i.test(textLower)) ||
      /unusual activity|security alert|security update required|security check required|account alert|account notice|please take action regarding your account|account may require attention|immediate review is suggested|update might be needed|verify details if necessary|security might be affected|action could be required|review may help avoid issues|kindly check once|submit documents for verification/i.test(
        textLower,
      ));

  const matchedIntentSignals: string[] = [];
  let intentRiskScore = 0;

  if (hasFinancialDemand) {
    matchedIntentSignals.push("financial demand");
    intentRiskScore += 35;
  }
  if (hasUrgencyPressure) {
    matchedIntentSignals.push("urgency pressure");
    intentRiskScore += 20;
  }
  if (hasAuthorityImpersonation) {
    matchedIntentSignals.push("authority impersonation");
    intentRiskScore += 15;
  }
  if (hasCredentialRequest) {
    matchedIntentSignals.push("credential request");
    intentRiskScore += 40;
  }
  if (hasMfaApprovalLure) {
    matchedIntentSignals.push("mfa approval lure");
    intentRiskScore += 30;
  }
  if (hasVoiceMessageSigninLure) {
    matchedIntentSignals.push("voice-message sign-in lure");
    intentRiskScore += 30;
  }
  if (hasGenericAccountMaintenance || hasAccountAlert) {
    matchedIntentSignals.push("account security prompt");
    intentRiskScore += 10;
  }
  if (hasActionContextCombo) {
    matchedIntentSignals.push("action + account/payment context");
    intentRiskScore += 18;
  }
  if (hasActionContextCombo && (hasUrgencyPressure || hasEscalatingConsequence)) {
    matchedIntentSignals.push("urgency + action + context");
    intentRiskScore += 25;
  }
  if (hasBecStyleTaskPressure) {
    matchedIntentSignals.push("possible business email compromise (BEC) pattern");
    intentRiskScore += 35;
  }
  if (
    textLower.trim().split(/\s+/).filter(Boolean).length <= 10 &&
    (hasActionContextCombo || (hasUrgencyPressure && hasCoreActionVerb) || hasEscalatingConsequence)
  ) {
    matchedIntentSignals.push("short high-risk directive");
    intentRiskScore += 15;
  } else if (textLower.trim().length <= 80 && (hasCredentialRequest || hasFinancialDemand || hasUrgencyPressure)) {
    matchedIntentSignals.push("short high-risk directive");
    intentRiskScore += 15;
  }
  if (dangerousVerbs.length > 0) {
    matchedIntentSignals.push("direct action request");
    intentRiskScore += 10;
  }

  const signalCount = [
    hasFinancialDemand,
    hasUrgencyPressure,
    hasAuthorityImpersonation,
    hasCredentialRequest,
  ].filter(Boolean).length;

  if (hasFinancialDemand && hasUrgencyPressure) {
    intentRiskScore += 20;
  }
  if (hasCredentialRequest && (hasUrgencyPressure || hasAuthorityImpersonation)) {
    intentRiskScore += 20;
  }
  if (signalCount >= 3) {
    intentRiskScore += 10;
  }
  if (isInformational) {
    intentRiskScore = Math.max(0, intentRiskScore - 15);
  }

  intentRiskScore = Math.min(100, intentRiskScore);

  // Determine intent type
  let intentType: IntentType;

  if (isSensitiveRequest || intentRiskScore >= 70) {
    intentType = "DANGEROUS";
  } else if ((isUserAskedToAct || intentRiskScore >= 40) && !isInformational) {
    intentType = "ACTION_REQUIRED";
  } else {
    intentType = "SAFE";
  }

  return {
    intentType,
    isUserAskedToAct,
    isSensitiveRequest,
    isInformational,
    hasAccountAlert,
    hasFinancialDemand,
    hasUrgencyPressure,
    hasAuthorityImpersonation,
    hasCredentialRequest,
    intentRiskScore,
    matchedIntentSignals,
    actionVerbs,
    sensitiveTerms,
    safeContextPhrases,
  };
}
