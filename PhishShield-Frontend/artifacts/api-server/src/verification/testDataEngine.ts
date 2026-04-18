import type { VerificationCase } from "./types.js";

function mulberry32(seed: number) {
  return function next() {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rng: () => number, values: readonly T[]): T {
  return values[Math.floor(rng() * values.length)] as T;
}

const BANKS = ["SBI", "HDFC", "ICICI", "Axis Bank", "Paytm", "PhonePe", "Google Pay"] as const;
const REWARD_AMOUNTS = ["₹2,500", "₹5,000", "₹9,999", "₹15,000", "₹25,000"] as const;
const URGENCY_LINES = [
  "Act within 2 hours to avoid suspension.",
  "Failure to respond today will block your access.",
  "Complete the action before 6 PM to avoid interruption.",
  "This is the final notice before permanent restriction.",
] as const;
const MALICIOUS_TLDS = ["xyz", "top", "icu", "click", "site"] as const;
const LEGIT_RECEIPTS = [
  "Your subscription renewed successfully and no action is required.",
  "This is an automated receipt for your recent payment.",
  "Your package is on the way and can be tracked from the official app.",
  "If this was not you, you can safely ignore this message.",
] as const;
const OBFUSCATED_PATTERNS = [
  "Please verify your O\u200BT\u200BP immediately by replying to this mail.",
  "P l e a s e  s e n d  y o u r  p a s s w o r d  n o w.",
  "Review the secure doc and confirm the beneficiary quietly before payroll closes.",
  "A confidential payment update is waiting for your immediate attention.",
] as const;
const HINDI_LINES = [
  "आपका खाता तुरंत बंद हो जाएगा। अभी सत्यापन करें।",
  "अपना KYC अभी अपडेट करें वरना सेवा रुक जाएगी।",
  "तुरंत OTP साझा करें ताकि आपका बैंक खाता चालू रहे।",
] as const;
const TELUGU_LINES = [
  "మీ ఖాతా బ్లాక్ అవుతుంది. వెంటనే క్లిక్ చేయండి.",
  "మీరు రివార్డ్ గెలుచుకున్నారు. ఇప్పుడే ధృవీకరించండి.",
  "మీ OTP ని వెంటనే పంపండి లేకపోతే సేవ నిలిపివేయబడుతుంది.",
] as const;
const SAFE_SENDERS = [
  "noreply@amazon.in",
  "no-reply@accounts.google.com",
  "info@mailer.netflix.com",
  "noreply@spotify.com",
  "updates@razorpay.com",
  "noreply@swiggy.in",
] as const;

function maliciousUrl(rng: () => number, brand: string, purpose: string) {
  const normalizedBrand = brand.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `http://${normalizedBrand}-${purpose}-${Math.floor(rng() * 900 + 100)}.${pick(rng, MALICIOUS_TLDS)}`;
}

function baseCase(
  id: string,
  suite: VerificationCase["suite"],
  name: string,
  emailText: string,
  expected: VerificationCase["expected"],
  extra?: Partial<VerificationCase>,
): VerificationCase {
  return {
    id,
    suite,
    name,
    emailText,
    expected,
    ...extra,
  };
}

export function generateVerificationCases(seed = 20260403): VerificationCase[] {
  const rng = mulberry32(seed);
  const cases: VerificationCase[] = [
    baseCase(
      "basic-safe-otp",
      "basic",
      "Legitimate OTP notification remains safe",
      "From: Amazon <account-update@amazon.com>\nSubject: Verify your new Amazon account\n\nUse this OTP to verify your sign in: 960878. Do not share this code with anyone. If this was not you, you can safely ignore this email.",
      { expectedClassification: "safe", maxScore: 29, requiresExplanation: true },
    ),
    baseCase(
      "basic-phish-otp",
      "basic",
      "Direct OTP harvesting request is blocked",
      "Subject: Urgent account review\n\nReply to this email with your OTP and password immediately to avoid suspension.",
      { expectedClassification: "phishing", minScore: 71, requiresHighlights: true },
    ),
    baseCase(
      "regression-amazon-otp-safe",
      "safe-email",
      "Amazon OTP notice with do-not-share stays safe",
      "From: Amazon <account-update@amazon.com>\nSubject: Verify your sign in\n\nUse this OTP to verify your Amazon login: 482931. Do not share this code with anyone. If this was not you, you can safely ignore this email.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-amazon-footer-otp-safe",
      "safe-email",
      "Amazon OTP notice with legal footer and warnings stays safe",
      "From: Amazon <account-update@amazon.com>\nSubject: Verify your new Amazon account\n\nTo verify your e-mail address, please use the following One Time Password (OTP): 960878. Don't share this OTP with anyone. Amazon Customer Service will never ask you to disclose or verify your Amazon password, OTP, credit card, or banking account number. If you receive a suspicious e-mail with a link to update your account information, do not click on the link—instead, report the e-mail to Amazon for investigation. Thank you. Amazon.com is a trading name for Amazon EU Sarl. Amazon.co.uk",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-google-login-alert-safe",
      "safe-email",
      "Google login alert with no action required stays safe",
      "From: Google <no-reply@accounts.google.com>\nSubject: New sign-in from Chrome\n\nWe noticed a new sign-in to your Google Account from Chrome on Windows. If this was you, no action is required. If this wasn't you, review your account activity from the official Google Security page.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-google-app-alert-safe",
      "safe-email",
      "Google app access alert that is informational stays safe",
      "From: Google Account Security <no-reply@accounts.google.com>\nSubject: A new app was blocked from accessing your account\n\nGoogle blocked a third-party app from accessing your Gmail because it looked suspicious. No action is required if you did not request this. You can review recent security activity from the official Google Account page.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-openai-promo-safe",
      "safe-email",
      "OpenAI Codex promo email stays safe despite marketing urgency language",
      "ChatGPT <noreply@email.openai.com>\nSubject: Try Codex for free\n\nTry Codex for free\nOpenAI’s coding agent — now in your ChatGPT plan\n\nTry Codex\nCodex is a coding agent that can do real work on your computer. It works alongside you to design, build, and iterate on software projects.\n\nFor a limited time, Codex is included in your ChatGPT plan at no additional cost.\n\nUse it to explore new ideas, solve hard problems, and move faster on your most important projects.\n\nWe can’t wait to see what you build.\n\nBest,\nThe Codex team\n\nChatGPT\n1455 3rd Street\nSan Francisco, CA 94158\nUnsubscribe\nPrivacy · Terms\nOpenAI © 2015–2026",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-openrouter-privacy-safe",
      "safe-email",
      "OpenRouter privacy and logging policy email stays safe",
      "From: OpenRouter Team <welcome@openrouter.ai>\nSubject: Protecting your data: logging and training policies\n\nHi Mohd,\n\nOpenRouter never logs your prompts or responses by default. We only store metadata to keep your service running smoothly: token counts and latency for billing, performance metrics for uptime optimization, and generation activity you can access anytime.\n\nEach provider has their own data retention and training policies, and you can check a straightforward summary here. By default, your paid requests never route to providers that train on your data. You can customize this further by setting data policies per request in your API calls, configuring account-wide settings in your privacy dashboard, and enabling Zero Data Retention (ZDR) for enterprise-grade privacy.\n\nWant to support model improvements? You may opt into prompt logging for a 1% usage discount, but that's entirely your choice.\n\nBest,\nOpenRouter Team\nUnsubscribe here.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-favtutor-newsletter-safe",
      "safe-email",
      "Beehiiv AI recap newsletter stays safe despite words like winner and today",
      "from: FavTutor <favtutor@mail.beehiiv.com>\nreply-to: FavTutor <newsletter@favtutor.net>\nto: \"mohdibadullah75@gmail.com\" <mohdibadullah75@gmail.com>\ndate: 23 Dec 2024, 11:40\nsubject: Google Search will have AI Mode soon to battle ChatGPT\nmailed-by: em2003.mail.beehiiv.com\nSigned by: mail.beehiiv.com\nunsubscribe: Unsubscribe from this sender\nsecurity: Standard encryption (TLS)\n\nDecember 23, 2024 | Read Online\n\nHello, AI Enthusiasts!\n\nWelcome to FavTutor’s AI Recap! We’ve gathered all the latest and important AI developments for the past 24 hours in one place, just for you.\n\nIn Today’s Newsletter:\n\nGoogle Search will have AI Mode soon to battle ChatGPT\nAdobe's new AI tool lets you create audio by humming sounds\nStudy: Claude AI cooperates better than OpenAI and Google models\n\nGoogle plans to add an \"AI mode\" button to its search interface.\n\nUnlock Windsurf Editor, by Codeium.\nDownload It Free Today\n\nUpdate your email preferences or unsubscribe here\n\n© 2024 FavTutor\n21 West 18th Street\nNew York, New York 10011",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-googlepay-gmail-spam-wrapper-safe",
      "safe-email",
      "Official Google Pay promo pasted from Gmail spam view stays safe",
      "Skip to content\nUsing Gmail with screen readers\nin:spam\n2 of 2\nSay hello to Flex. A credit card by Google Pay\nSpam\nGoogle Pay <googlepay-noreply@google.com>\nSat 21 Mar 2026\nmailing list: <6d3aed9a6ec533bc3e46c9ecd4624fe5ea4a5b3e.google.com>\nmailed-by: scoutcamp.bounces.google.com\nSigned by: google.com\nWhy is this message in spam? This message is similar to messages that were identified as spam in the past.\nReport as not spam\n\nIntroducing Flex by Google Pay. The credit card, simplified. Built on the RuPay network and issued in partnership with Axis Bank.\n\nApply now\n\nSet up in seconds. No paperwork, no queues. Unlock welcome benefits worth ₹500.\nEarn instant and real rewards. Up to 8 stars for every ₹500 spent.\nRepay flexibly, always.\n\nHave questions? Visit the Help Center.\n\nYou're getting this email because your settings show that you'd like to know about Google Pay tips. If you don't want to receive such emails in the future, please change your notification settings or unsubscribe here.\n\n© 2026 Google India Digital Services Private Limited",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-aws-sns-safe",
      "safe-email",
      "AWS SNS test notification with official unsubscribe links stays safe",
      "Skip to content\nUsing Gmail with screen readers\nEnable desktop notifications for Gmail. OK No, thanks\n81 of 976\nTest Mail\nInbox\n\nAWS Notifications <no-reply@sns.amazonaws.com>\nfrom: AWS Notifications <no-reply@sns.amazonaws.com>\nto: mohdibadullah13@gmail.com\ndate: 13 Mar 2026, 10:35\nsubject: Test Mail\nmailed-by: amazonses.com\nSigned by: sns.amazonaws.com\nsecurity: Standard encryption (TLS)\nThis is SNS Test\n--\nIf you wish to stop receiving notifications from this topic, please click or visit the link below to unsubscribe:\nhttps://sns.us-east-1.amazonaws.com/unsubscribe.html?SubscriptionArn=arn:aws:sns:us-east-1:199155173678:MyEmailTopic-ibad:dcb78741-2882-4881-8f4f-f7068af150bd&Endpoint=mohdibadullah13@gmail.com\nPlease do not reply directly to this email. If you have any questions or comments regarding this email, please contact us at https://aws.amazon.com/support",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-huggingface-confirmation-safe",
      "safe-email",
      "Official Hugging Face email confirmation stays safe",
      "Skip to content\nUsing Gmail with screen readers\n13 of 976\n[Hugging Face] Click this link to confirm your email address\nInbox\n\nhuggingface <website@huggingface.co>\nfrom: huggingface <website@huggingface.co>\nto: mohdibadullah13@gmail.com\ndate: 30 Mar 2026, 11:12\nsubject: [Hugging Face] Click this link to confirm your email address\nmailed-by: amazonses.com\nSigned by: huggingface.co\nsecurity: Standard encryption (TLS)\nConfirm your email address by clicking on this link:\nhttps://huggingface.co/email_confirmation/sOwGHvZaIrIIlbjrcNiBVSVhKDGh\n\nIf you didn't create a Hugging Face account, you can ignore this email.\n\nHugging Face: The AI community building the future.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-quora-digest-safe",
      "safe-email",
      "Quora digest newsletter with salary or GST content stays safe",
      "Skip to content\nUsing Gmail with screen readers\n7 of 3272\nGross Salary Rs. 90457 after Deduction it is around Rs.77000. Along with this my wife ...\nInbox\n\nQuora Digest <english-quora-digest@quora.com> Unsubscribe\nfrom: Quora Digest <english-quora-digest@quora.com>\nto: mohdibadullah13@gmail.com\ndate: 2 Apr 2026, 06:04\nsubject: Gross Salary Rs. 90457 after Deduction it is around Rs.77000. Along with this my wife ...\nmailed-by: quora.com\nSigned by: quora.com\nsecurity: Standard encryption (TLS)\nTop stories for Mohd\nWhat is the salary after SSC CGL?\nSatyam, Inspector at Central Board of Excise and Customs (2023-present)\nI have been working as a GST Inspector...\nRead more in your feed\nNever miss a story. Designed for readers on the go.\nIf you don't want to receive this type of email in the future, please unsubscribe.\nhttps://www.quora.com",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-microsoft-collaboration-safe",
      "safe-email",
      "Official Microsoft collaboration notice stays safe",
      "From: Microsoft OneDrive <noreply@onedrive.com>\nSubject: Priya shared \"Quarterly Hiring Plan.xlsx\" with you\n\nHi there,\n\nPriya shared a file with you using Microsoft OneDrive for Business.\n\nOpen in OneDrive\n\nYou're receiving this email because priya@contoso.com shared a file with you.\nManage notification settings\nPrivacy Statement\nMicrosoft Corporation, One Microsoft Way, Redmond, WA 98052",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-dropbox-folder-share-safe",
      "safe-email",
      "Dropbox folder share stays safe",
      "From: Dropbox <no-reply@dropbox.com>\nSubject: Chris shared a folder with you\n\nChris shared the folder \"Design Assets\" with you. Open in Dropbox to view the files. Manage notification settings anytime.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-zoom-meeting-invite-safe",
      "safe-email",
      "Zoom meeting invite stays safe",
      "From: Zoom <no-reply@zoom.us>\nSubject: Meeting invitation: Product Review\n\nJoin Zoom Meeting at the scheduled time. Passcode: 553921. For your security, do not share this link publicly.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-google-drive-share-safe",
      "safe-email",
      "Google Drive share stays safe",
      "From: Google Drive <drive-shares-noreply@google.com>\nSubject: Aisha shared \"Q2 Launch Plan\" with you\n\nAisha shared a file with you using Google Drive. View in Google Docs. You're receiving this email because a file was shared with you. Manage notification settings.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-docusign-request-safe",
      "safe-email",
      "DocuSign request stays safe",
      "From: DocuSign <dse@docusign.net>\nSubject: Document ready for signature\n\nPlease review and sign the attached agreement in DocuSign. This secure message was sent via DocuSign. Privacy Statement.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-bank-otp-safe",
      "safe-email",
      "Bank OTP notice with do-not-share stays safe",
      "From: HDFC Bank <alerts@hdfcbank.com>\nSubject: OTP for card transaction\n\nYour OTP for transaction verification is 114422. Do not share this OTP with anyone, including bank staff.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "regression-hinglish-safe-otp",
      "safe-email",
      "Hinglish OTP warning with share-mat-karo remains safe",
      "Amazon: OTP 123456. Isko kisi ke saath share mat karo.",
      { expectedClassification: "safe", expectedConfidenceLevel: "HIGH", maxScore: 25, requiresExplanation: true },
    ),
    baseCase(
      "basic-uncertain-alert",
      "basic",
      "Vague account alert lands in the suspicious band",
      "Subject: Unusual activity detected\n\nWe noticed unusual activity on your account. Please review your settings when possible.",
      { expectedClassification: "uncertain", minScore: 30, maxScore: 70, requiresExplanation: true },
    ),
    baseCase(
      "regression-crypto-double-money",
      "phishing-detection",
      "Crypto doubling scam is never marked safe",
      "Subject: Instant crypto return\n\nSend 0.1 BTC to this wallet and get 0.2 BTC instantly.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-pin-request",
      "phishing-detection",
      "Credential-only PIN request is blocked",
      "Subject: Identity confirmation\n\nConfirm your identity by entering your PIN immediately.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-customs-fee-phish",
      "phishing-detection",
      "Customs payment pressure scam is blocked",
      "Subject: DHL parcel held at customs\n\nYour parcel is waiting for delivery. Pay the customs release fee in the next 2 hours to avoid return to sender. Reply once payment is complete.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-callback-support-scam",
      "phishing-detection",
      "Invoice callback scam with a phone number is phishing",
      "Subject: Geek Squad Auto Renewal Notice\n\nYour plan will auto-renew today for $389.99. If you did not authorize this charge, call our billing desk immediately at +1 (808) 555-4412 to cancel and stop the payment.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-telegram-job-scam",
      "phishing-detection",
      "Telegram recruiter scam with deposit is phishing",
      "Subject: Remote role selected\n\nDear Applicant, you have been selected for a remote data-entry role. Contact our hiring manager on Telegram @HiringManager_Official to continue. Equipment setup requires a refundable deposit of $120 today.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-credit-offer-bait",
      "phishing-detection",
      "Pre-approved credit bait with untrusted apply link is phishing",
      "Subject: Limited-time credit offer\n\nYou are pre-approved for a low-interest credit offer. Check your eligibility now at https://fast-credit-checks.co/apply before the offer expires.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-subscription-cancel-bait",
      "phishing-detection",
      "Subscription renewal cancellation lure is phishing",
      "Subject: Subscription renewal notice\n\nYour subscription will renew on April 10. If you wish to cancel, click https://manage-subscription-now.com before your payment method is charged automatically.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-browser-extension-lure",
      "phishing-detection",
      "Browser extension and sign-in approval lure is phishing",
      "Subject: Secure webmail extension required\n\nTo continue using corporate webmail, install the browser extension immediately and approve the sign-in request today to maintain access.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-sharepoint-consent-lure",
      "phishing-detection",
      "Shared-document consent lure is phishing",
      "Subject: SharePoint secure review\n\nA secure Microsoft 365 document has been shared with you. Review the file now and approve the sign-in request within the next 30 minutes to keep access.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-google-oauth-consent-phish",
      "phishing-detection",
      "Google OAuth consent lure on a legitimate domain is phishing",
      "From: Google Workspace <no-reply@google.com>\nSubject: Review requested app permissions\n\nHR Docs Sync is requesting access to your Gmail and Drive. Review and allow the app to continue using your workspace account: https://accounts.google.com/o/oauth2/v2/auth?client_id=123&scope=https://mail.google.com/",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-slack-workspace-access-lure",
      "phishing-detection",
      "Slack workspace access lure is phishing",
      "Subject: Slack secure notice\n\nA protected Slack file is pending. Open the secure thread and confirm your login details now to keep workspace access.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-mfa-fatigue-lure",
      "phishing-detection",
      "MFA approval fatigue lure is phishing",
      "Subject: Microsoft security alert\n\nUnexpected sign-in detected. Open Microsoft Authenticator and approve the request now to keep access to your mailbox.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-okta-mfa-lockout-lure",
      "phishing-detection",
      "Okta MFA lockout lure is phishing",
      "Subject: Okta verification pending\n\nApprove the pending sign-in now and confirm your company login details to avoid workspace lockout.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-adobe-sign-lure",
      "phishing-detection",
      "Adobe-style sign-in lure is phishing",
      "From: Adobe Sign <no-reply@adobesign-review.com>\nSubject: Secure document pending\n\nA secure document is waiting. Sign in with Microsoft 365 now to review the protected file and keep access active.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-servicenow-lockout-lure",
      "phishing-detection",
      "ServiceNow-style lockout lure is phishing",
      "From: ServiceNow Support <helpdesk@servicenow-access.net>\nSubject: VPN access verification required\n\nRe-enter your company credentials now to avoid account lockout and restore remote access.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-svg-voicemail-lure",
      "phishing-detection",
      "SVG voicemail sign-in lure is phishing",
      "Subject: New secure voice message\n\nOpen the attached SVG voice message and sign in to hear the recording now.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-svg-attachment-only-lure",
      "phishing-detection",
      "Standalone SVG attachment lure is phishing",
      "Subject: New voice message\n\nPlease see the attached message.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Voice_Message_8831.svg", contentType: "image/svg+xml" }],
      },
    ),
    baseCase(
      "regression-onenote-attachment-lure",
      "phishing-detection",
      "OneNote invoice attachment lure is phishing",
      "Subject: Updated invoice copy\n\nAttached is the updated invoice for review.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Updated_Invoice.one", contentType: "application/onenote" }],
      },
    ),
    baseCase(
      "regression-shortcut-attachment-lure",
      "phishing-detection",
      "Internet shortcut attachment lure is phishing",
      "Subject: Shared account statement\n\nPlease open the attached statement shortcut to review the secure copy.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Account_Statement.url", contentType: "application/internet-shortcut" }],
      },
    ),
    baseCase(
      "regression-eml-container-lure",
      "phishing-detection",
      "Attached email container lure is phishing",
      "Subject: Secure mailbox update\n\nOpen the attached email file and confirm your sign-in details immediately to keep mailbox access.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Secure_Message.eml", contentType: "message/rfc822" }],
      },
    ),
    baseCase(
      "regression-iso-attachment-lure",
      "phishing-detection",
      "ISO voicemail lure is phishing",
      "Subject: Voicemail protected delivery\n\nMount the attached disk image to hear the secure voicemail and re-authenticate now.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Voice_Message.iso", contentType: "application/octet-stream" }],
      },
    ),
    baseCase(
      "regression-safe-pdf-attachment",
      "safe-email",
      "Routine PDF attachment stays safe",
      "From: Operations <ops@contoso.com>\nSubject: Monthly report\n\nAttached is the final PDF report for your records. No action is required.",
      {
        expectedClassification: "safe",
        expectedConfidenceLevel: "HIGH",
        maxScore: 25,
        requiresExplanation: true,
      },
      {
        attachments: [{ filename: "monthly-report.pdf", contentType: "application/pdf" }],
      },
    ),
    baseCase(
      "regression-qr-pdf-lure",
      "phishing-detection",
      "QR-in-PDF payroll lure is phishing",
      "Subject: Secure payroll update\n\nScan the QR code in the attached PDF to keep access to payroll active.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Payroll_Update.pdf", contentType: "application/pdf", hasQrCode: true }],
      },
    ),
    baseCase(
      "regression-password-archive-lure",
      "phishing-detection",
      "Password-protected archive lure is phishing",
      "Subject: Secure document delivery\n\nOpen the password protected archive and use the code below to review the document.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
      {
        attachments: [{ filename: "Secure_Documents.zip", contentType: "application/zip", isPasswordProtected: true }],
      },
    ),
    baseCase(
      "regression-safe-source-archive",
      "safe-email",
      "Internal source archive stays safe",
      "From: Engineering Build Bot <buildbot@contoso.com>\nSubject: Approved source bundle\n\nAttached is the approved source archive for internal testing only. No action is required.",
      {
        expectedClassification: "safe",
        expectedConfidenceLevel: "HIGH",
        maxScore: 25,
        requiresExplanation: true,
      },
      {
        attachments: [{ filename: "project-source.zip", contentType: "application/zip" }],
      },
    ),
    baseCase(
      "regression-thread-hijack-beneficiary-change",
      "phishing-detection",
      "Thread-hijack beneficiary change request is phishing",
      "Subject: Re: April remittance\n\nAs discussed, we changed the beneficiary for this invoice. Process the transfer today and send confirmation once done. I'm in a meeting and can't talk right now.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-parcel-redelivery-fee",
      "phishing-detection",
      "Parcel redelivery fee scam is phishing",
      "Subject: UPS redelivery required\n\nYour parcel could not be delivered. Pay the redelivery fee tonight to avoid return to sender and reply once payment is completed.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-short-verify-now", 
      "edge-cases",
      "Very short urgency text is never treated as safe",
      "Verify now",
      {
        expectedClassification: "uncertain",
        acceptableLabels: ["uncertain", "phishing"],
        expectedConfidenceLevel: ["MEDIUM", "HIGH"],
        minScore: 30,
        maxScore: 100,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-bare-suspicious-link",
      "edge-cases",
      "Standalone suspicious-TLD URL is never marked safe",
      "http://random-link.xyz",
      {
        expectedClassification: "uncertain",
        acceptableLabels: ["uncertain", "phishing"],
        expectedConfidenceLevel: ["MEDIUM", "HIGH"],
        minScore: 30,
        maxScore: 100,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-verify-here-malicious-link",
      "phishing-detection",
      "Short verify-here link lure is treated as phishing",
      "Verify here: http://portal-review-123.xyz/verify",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-click-link-avoid-suspension",
      "phishing-detection",
      "Short click-link suspension warning is treated as phishing",
      "Click link to avoid suspension",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-generic-security-update",
      "edge-cases",
      "Generic security update prompt stays suspicious not phishing",
      "Update your account details for security",
      {
        expectedClassification: "uncertain",
        expectedConfidenceLevel: "MEDIUM",
        minScore: 30,
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-confirm-email-address",
      "edge-cases",
      "Confirm your email address stays suspicious not phishing",
      "Confirm your email address",
      {
        expectedClassification: "uncertain",
        expectedConfidenceLevel: "MEDIUM",
        minScore: 30,
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-update-your-info",
      "edge-cases",
      "Update your info is never treated as fully safe",
      "Update your info",
      {
        expectedClassification: "uncertain",
        expectedConfidenceLevel: "MEDIUM",
        minScore: 30,
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-hinglish-otp-hard",
      "multilingual",
      "Hinglish OTP account-block warning escalates to phishing",
      "Tumhara account block hone wala hai. Jaldi OTP bhej warna access band ho jayega permanently.",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        expectedLanguage: ["en", "mixed"],
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-job-fee-short-no-amount",
      "phishing-detection",
      "HR pay-fee job confirmation prompt is phishing",
      "HR: pay fee to confirm job",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-suspicious-login-confirm-identity",
      "phishing-detection",
      "Suspicious login confirm identity is phishing",
      "Suspicious login, confirm identity",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-confirm-details-avoid-closure",
      "phishing-detection",
      "Confirm details to avoid closure is phishing",
      "Confirm details to avoid closure",
      {
        expectedClassification: "phishing",
        expectedConfidenceLevel: "HIGH",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-security-update-required-suspicious",
      "edge-cases",
      "Security update required stays suspicious not phishing",
      "Security update required",
      {
        expectedClassification: "uncertain",
        expectedConfidenceLevel: "MEDIUM",
        minScore: 30,
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-security-check-required-suspicious",
      "edge-cases",
      "Security check required stays suspicious not phishing",
      "Security check required",
      {
        expectedClassification: "uncertain",
        expectedConfidenceLevel: "MEDIUM",
        minScore: 30,
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-password-changed-successfully-safe",
      "safe-email",
      "Password changed successfully notification stays safe",
      "Password changed successfully (legit)",
      {
        expectedClassification: "safe",
        expectedConfidenceLevel: "HIGH",
        maxScore: 25,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-paytm-kyc-no-link",
      "phishing-detection",
      "No-link Paytm KYC suspension scam escalates correctly",
      "Subject: Paytm KYC pending\n\nYour Paytm KYC verification is pending. Complete verification immediately to avoid wallet suspension.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-reward-no-link",
      "phishing-detection",
      "No-link cashback reward scam is blocked",
      "Subject: Cashback prize\n\nCongratulations! You won ₹5000 cashback. Claim now to receive the reward.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-job-fee-scam",
      "phishing-detection",
      "Job selection fee scam is never marked safe",
      "Subject: Candidate selection notice\n\nDear Candidate, Pay ₹499 to confirm your job selection.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-hindi-bank-threat",
      "multilingual",
      "Hindi bank closure threat escalates to phishing",
      "प्रिय ग्राहक,\nआपका बैंक खाता बंद होने वाला है। कृपया सत्यापन करें।",
      {
        expectedClassification: "phishing",
        minScore: 71,
        expectedLanguage: ["hi", "mixed"],
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-telugu-bank-threat",
      "multilingual",
      "Telugu bank blocked warning escalates to phishing",
      "మీ బ్యాంక్ ఖాతా నిలిపివేయబడింది. వెంటనే ధృవీకరించండి.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        expectedLanguage: ["te", "mixed"],
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-invoice-payment-fraud",
      "phishing-detection",
      "Urgent invoice payment request is treated as phishing",
      "Subject: Payment follow-up\n\nPlease check attached invoice and confirm payment urgently.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-urgent-transfer-meeting",
      "phishing-detection",
      "Urgent transfer request while in a meeting is treated as BEC phishing",
      "Hi, I need you to transfer funds urgently. I am in a meeting. Will explain later.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-hinglish-otp-pressure",
      "multilingual",
      "Hinglish OTP pressure scam escalates to phishing",
      "Bhai OTP bhej jaldi warna account block ho jayega",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
        requiresHighlights: true,
      },
    ),
    baseCase(
      "regression-generic-account-update",
      "edge-cases",
      "Generic account update prompt is never treated as fully safe",
      "Update your account information to continue.",
      {
        expectedClassification: "uncertain",
        acceptableLabels: ["uncertain", "phishing"],
        minScore: 30,
        maxScore: 100,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-tax-notice-details",
      "phishing-detection",
      "Income tax notice demanding details is treated as phishing",
      "Income tax notice: submit details immediately",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-payment-failed-card-update",
      "phishing-detection",
      "Payment failure asking for card updates is phishing",
      "Payment failed, update card details",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-cursor-billing-dashboard-notice",
      "safe-email",
      "Legitimate billing issue notices that point to the official dashboard are not treated as phishing",
      "Subject: Couldn't process payment\nFrom: Cursor <hi@cursor.com>\n\nHi,\n\nThank you for using Cursor!\n\nWe've encountered an issue processing your subscription payment. You can address this by visiting the Billing & Invoices section in your dashboard. For reference, your account is registered with your email.\n\nIf you need any help, reply to this email or reach out to us at hi@cursor.com.\n\nBest,\nCursor Team",
      {
        expectedClassification: "safe",
        acceptableLabels: ["safe", "uncertain"],
        maxScore: 60,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-aws-account-alert-safe-exact",
      "safe-email",
      "Official AWS billing authorization notices with valid AWS domains are treated as safe",
      "Subject: Amazon Web Services Account Alert\nfrom: no-reply@amazonaws.com <no-reply@amazonaws.com>\nto: mohdibadullah75@gmail.com\ndate: 15 Oct 2025, 14:09\nsubject: Amazon Web Services Account Alert\nmailed-by: amazonses.com\nSigned by: amazonaws.com\nsecurity: Standard encryption (TLS)\n\nGreetings from Amazon Web Services,\n\nWe received an error while confirming the payment method associated with your Amazon Web Services account.\n\nTo use some Amazon Web Services, you must provide a valid payment method. You can verify your current payment method or choose to add another payment method at the following page:\n\nhttps://console.aws.amazon.com/billing/home#/paymentmethods\n\nSome common reasons why an authorization might fail are:\n\n* Your bank may decline authorizations if the CVV2 security code was not requested. Your bank may be able to temporarily lift this requirement.\n\n* The authorization is for a low dollar amount ($1.00) which your bank may decline.\n\n* If you signed up for multiple AWS services, a $1.00 authorization may be performed for each service. Your bank may approve the first authorization and decline subsequent ones depending on their security policies.\n\n* Some banks have restrictions on Internet transactions. You may want to check with your credit card company to see if they have such a restriction.\n\nWe recommend you contact your bank to determine the exact reason for the decline, or to ask them to take steps on their end to approve the authorization. Once your bank is ready to approve the authorization, please contact us back and we will retry this authorization for you.\n\nhttps://aws-portal.amazon.com/gp/aws/html-forms-controller/contactus/aws-account-and-billing\n\nYou can contact AWS Customer Service via the Support Center: https://aws.amazon.com/support\n\nIf you feel you have received this e-mail in error, please include these details in your case.\n\nThank you for using Amazon Web Services.\n\nSincerely,\n\nAmazon Web Services",
      {
        expectedClassification: "safe",
        acceptableLabels: ["safe", "uncertain"],
        maxScore: 30,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-short-verification-required",
      "phishing-detection",
      "Short verification-required prompt is never safe",
      "Immediate verification required",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-login-activity-generic",
      "edge-cases",
      "Generic login activity alert stays at least uncertain",
      "Login activity detected",
      {
        expectedClassification: "uncertain",
        acceptableLabels: ["uncertain", "phishing"],
        minScore: 30,
        maxScore: 100,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-hinglish-service-band-payment",
      "multilingual",
      "Hinglish payment pressure with service-block threat is phishing",
      "Jaldi payment karo nahi toh service band ho jayegi",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-profile-disruption-short",
      "phishing-detection",
      "Profile verification with disruption threat escalates to phishing",
      "Verify your profile to avoid disruption",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-bec-unavailable-task",
      "phishing-detection",
      "Unavailable-task urgency request is treated as phishing",
      "I’m unavailable, handle this task urgently",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-bec-complete-task-urgent",
      "phishing-detection",
      "Unavailable request with a vague urgent task is treated as phishing",
      "I'm currently unavailable, complete this task urgently",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-payment-reminder-service-disruption",
      "phishing-detection",
      "Pending invoice reminder with service disruption is phishing",
      "Subject: Payment Reminder\nPlease pay your pending invoice immediately to avoid service disruption.",
      {
        expectedClassification: "phishing",
        minScore: 71,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-order-confirmation-safe-long",
      "safe-email",
      "Long order confirmation remains safe",
      "Subject: Order Confirmation\n\nHello,\n\nThank you for your recent purchase. Your order has been successfully placed and is currently being processed.\n\nYou will receive tracking details shortly once the shipment is dispatched.",
      {
        expectedClassification: "safe",
        maxScore: 25,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "regression-feedback-request-safe",
      "safe-email",
      "Feedback request stays safe",
      "Feedback request",
      {
        expectedClassification: "safe",
        maxScore: 29,
        requiresExplanation: true,
      },
    ),
    baseCase(
      "edge-empty",
      "edge-cases",
      "Empty email does not crash the pipeline",
      "",
      { expectedClassification: "safe", minScore: 0, maxScore: 5, requiresExplanation: true },
    ),
    baseCase(
      "edge-short-safe",
      "edge-cases",
      "Single-line benign message remains safe",
      "Thanks.",
      { expectedClassification: "safe", maxScore: 29, requiresExplanation: true },
    ),
    baseCase(
      "header-spoof-fixed",
      "header-spoofing",
      "Reply-To mismatch is surfaced in header analysis",
      "Subject: Payroll verification\n\nPlease confirm the updated payroll beneficiary before 4 PM today.",
      {
        expectedClassification: "uncertain",
        acceptableLabels: ["safe", "uncertain", "phishing"],
        minScore: 0,
        maxScore: 100,
        requiresHeaderAnalysis: true,
        requiresExplanation: true,
      },
      {
        headersText:
          'From: "Finance Desk" <alerts@company-payroll.com>\nReply-To: payout-review@secure-payroll-reset.xyz\nReturn-Path: bounce@mailer-reset.top\nReceived: from unknown-host.example',
      },
    ),
  ];

  for (let i = 0; i < 14; i++) {
    const bank = pick(rng, BANKS);
    const url = maliciousUrl(rng, bank, "kyc-verify");
    const amount = pick(rng, REWARD_AMOUNTS);
    const urgency = pick(rng, URGENCY_LINES);

    cases.push(
      baseCase(
        `bank-phish-${i}`,
        "phishing-detection",
        `${bank} KYC or suspension phishing #${i + 1}`,
        `From: ${bank} Security <alerts@${bank.toLowerCase().replace(/\s+/g, "")}-support.${pick(rng, MALICIOUS_TLDS)}>\nSubject: Critical ${bank} account review\n\nDear customer, your ${bank} profile requires urgent KYC verification. Visit ${url} now and confirm your banking details. ${urgency} Reward reference: ${amount}.`,
        {
          expectedClassification: "phishing",
          minScore: 71,
          requiresUrlAnalysis: true,
          requiresHighlights: true,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 10; i++) {
    const bank = pick(rng, BANKS);
    cases.push(
      baseCase(
        `otp-phish-${i}`,
        "phishing-detection",
        `OTP reply scam #${i + 1}`,
        `Subject: ${bank} verification pending\n\nTo keep your wallet active, reply with the OTP sent to your phone, your UPI PIN, and the last four digits of your card immediately. ${pick(rng, URGENCY_LINES)}`,
        {
          expectedClassification: "phishing",
          minScore: 71,
          requiresHighlights: true,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 10; i++) {
    const bank = pick(rng, BANKS);
    const url = maliciousUrl(rng, bank, "reward");
    const amount = pick(rng, REWARD_AMOUNTS);
    cases.push(
      baseCase(
        `reward-phish-${i}`,
        "phishing-detection",
        `Reward scam #${i + 1}`,
        `Subject: Congratulations! Claim ${amount} cashback\n\nYou have been selected for a ${bank} loyalty reward. Confirm your details and claim the amount at ${url}. Offer expires tonight.`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["uncertain", "phishing"],
          minScore: 30,
          maxScore: 100,
          requiresUrlAnalysis: true,
          requiresHighlights: true,
        },
      ),
    );
  }

  for (let i = 0; i < 10; i++) {
    const sender = pick(rng, SAFE_SENDERS);
    cases.push(
      baseCase(
        `safe-receipt-${i}`,
        "safe-email",
        `Legitimate transactional receipt #${i + 1}`,
        `From: Service Team <${sender}>\nSubject: Payment confirmation\n\n${pick(rng, LEGIT_RECEIPTS)} Transaction ID: TXN-${Math.floor(rng() * 900000 + 100000)}. Thanks for using our service.`,
        {
          expectedClassification: "safe",
          maxScore: 29,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 10; i++) {
    const sender = pick(rng, SAFE_SENDERS);
    cases.push(
      baseCase(
        `safe-security-${i}`,
        "safe-email",
        `Legitimate security notification #${i + 1}`,
        `From: Security Team <${sender}>\nSubject: Sign-in confirmation\n\nA new sign in was detected on your account. If this was not you, you can securely review activity from the official website. Do not share your OTP with anyone.`,
        {
          expectedClassification: "safe",
          acceptableLabels: ["safe", "uncertain"],
          maxScore: 70,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 8; i++) {
    const url = maliciousUrl(rng, pick(rng, BANKS), "doc-review");
    cases.push(
      baseCase(
        `transformer-semantic-${i}`,
        "transformer-only",
        `Clean-looking enterprise phishing #${i + 1}`,
        `Subject: Secure document shared with you\n\nA private Microsoft 365 document requires your review today. Open the secure workspace and approve access at ${url} to continue the workflow.`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["uncertain", "phishing"],
          minScore: 30,
          maxScore: 100,
          requiresUrlAnalysis: true,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 8; i++) {
    cases.push(
      baseCase(
        `obfuscated-phish-${i}`,
        "phishing-detection",
        `Obfuscated phishing variant #${i + 1}`,
        `Subject: Action required\n\n${pick(rng, OBFUSCATED_PATTERNS)} Visit ${maliciousUrl(rng, "secure", "review")} to continue.`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["uncertain", "phishing"],
          minScore: 30,
          maxScore: 100,
          requiresHighlights: true,
          requiresUrlAnalysis: true,
        },
      ),
    );
  }

  for (let i = 0; i < 8; i++) {
    cases.push(
      baseCase(
        `uncertain-case-${i}`,
        "edge-cases",
        `Ambiguous account alert #${i + 1}`,
        `Subject: Account notice\n\nWe noticed an unusual sign-in attempt on your mailbox. Please review recent activity from the official app if needed.`,
        {
          expectedClassification: "uncertain",
          minScore: 30,
          maxScore: 70,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 8; i++) {
    const hindi = pick(rng, HINDI_LINES);
    cases.push(
      baseCase(
        `hindi-phish-${i}`,
        "multilingual",
        `Hindi phishing email #${i + 1}`,
        `Subject: SBI खाता चेतावनी\n\n${hindi} अभी क्लिक करें: ${maliciousUrl(rng, "sbi", "khata")}`,
        {
          expectedClassification: "phishing",
          minScore: 71,
          expectedLanguage: ["hi", "mixed"],
          requiresUrlAnalysis: true,
          requiresHighlights: true,
        },
      ),
    );
  }

  for (let i = 0; i < 8; i++) {
    const telugu = pick(rng, TELUGU_LINES);
    cases.push(
      baseCase(
        `telugu-phish-${i}`,
        "multilingual",
        `Telugu phishing email #${i + 1}`,
        `Subject: ఖాతా నిర్ధారణ\n\n${telugu} ${maliciousUrl(rng, "upi", "bonus")}`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["uncertain", "phishing"],
          minScore: 30,
          maxScore: 100,
          expectedLanguage: ["te", "mixed"],
          requiresUrlAnalysis: true,
          requiresHighlights: true,
        },
      ),
    );
  }

  for (let i = 0; i < 10; i++) {
    const safeUrl = `https://www.google.com/security?ref=${Math.floor(rng() * 1000)}`;
    const badUrl = maliciousUrl(rng, "google", "verify-login");
    cases.push(
      baseCase(
        `url-analysis-${i}`,
        "url-analysis",
        `URL analysis catches suspicious destination #${i + 1}`,
        `Subject: Security update\n\nIf this was you, ignore this notice. Otherwise review activity at ${safeUrl}. Attackers may also send you to ${badUrl} pretending to be support.`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["uncertain", "phishing"],
          minScore: 30,
          maxScore: 100,
          requiresUrlAnalysis: true,
          requiresExplanation: true,
        },
      ),
    );
  }

  for (let i = 0; i < 7; i++) {
    const bank = pick(rng, BANKS);
    cases.push(
      baseCase(
        `header-spoof-${i}`,
        "header-spoofing",
        `Header spoof attempt #${i + 1}`,
        `Subject: ${bank} urgent notice\n\nPlease review the secure attachment and confirm your details today.`,
        {
          expectedClassification: "uncertain",
          acceptableLabels: ["safe", "uncertain", "phishing"],
          minScore: 0,
          maxScore: 100,
          requiresHeaderAnalysis: true,
          requiresExplanation: true,
        },
        {
          headersText:
            `From: "${bank} Security" <alerts@${bank.toLowerCase().replace(/\s+/g, "")}.com>\nReply-To: remediation@${bank.toLowerCase().replace(/\s+/g, "")}-review.${pick(rng, MALICIOUS_TLDS)}\nReturn-Path: bounce@compromised-mail.${pick(rng, MALICIOUS_TLDS)}`,
        },
      ),
    );
  }

  return cases;
}

export function getPerformanceCases(seed = 20260403, count = 120): VerificationCase[] {
  return generateVerificationCases(seed).slice(0, count);
}

export function getLlmFallbackCase(): VerificationCase {
  return baseCase(
    "llm-fallback-midrange",
    "llm-fallback",
    "LLM fallback is triggered for a mid-range ambiguous alert",
    "Subject: Security alert\n\nWe noticed unusual activity on your mailbox and your account may be blocked soon. Please contact support to confirm this notice.",
    {
      expectedClassification: "phishing",
      minScore: 71,
      requiresExplanation: true,
      requiresLLMUsage: true,
    },
  );
}

export function getIntegrationSmokeCases(): VerificationCase[] {
  return [
    baseCase(
      "integration-safe",
      "integration",
      "HTTP safe email analysis",
      "From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nA new sign in was detected. If this was you, no action is required.",
      { expectedClassification: "safe", maxScore: 29, requiresExplanation: true },
    ),
    baseCase(
      "integration-phishing",
      "integration",
      "HTTP phishing analysis",
      "Subject: Verify your account immediately\n\nReply with your OTP and password to restore access now: http://secure-access-reset.xyz/login",
      { expectedClassification: "phishing", minScore: 71, requiresUrlAnalysis: true, requiresHighlights: true },
    ),
  ];
}

export function getConsistencyCases(): VerificationCase[] {
  return [
    baseCase(
      "consistency-safe",
      "consistency",
      "Repeated safe notification stays stable",
      "From: Google <no-reply@accounts.google.com>\nSubject: Sign-in alert\n\nA new sign in was detected. If this was you, no action is required.",
      { expectedClassification: "safe", maxScore: 29, requiresExplanation: true },
    ),
    baseCase(
      "consistency-uncertain",
      "consistency",
      "Repeated borderline alert stays stable",
      "Subject: Account notice\n\nWe noticed unusual activity on your mailbox. Please review recent activity from the official app if needed.",
      { expectedClassification: "uncertain", minScore: 30, maxScore: 70, requiresExplanation: true },
    ),
    baseCase(
      "consistency-phishing",
      "consistency",
      "Repeated phishing lure stays stable",
      "Subject: Urgent verification required\n\nReply with your OTP and password immediately to restore access: http://secure-access-reset.xyz/login",
      { expectedClassification: "phishing", minScore: 71, requiresUrlAnalysis: true, requiresHighlights: true },
    ),
  ];
}

