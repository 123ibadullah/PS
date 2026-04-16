/**
 * Adversarial attack detection for phishing emails
 * Detects various evasion techniques used by attackers to bypass detection
 */

import { logger } from './logger.js';

export interface AdversarialDetectionResult {
    /** Whether any adversarial techniques were detected */
    detected: boolean;
    /** List of detected adversarial techniques */
    techniques: string[];
    /** Confidence score (0-100) */
    confidence: number;
    /** Normalized text after removing adversarial artifacts */
    normalizedText: string;
    /** Explanation of detected techniques */
    explanation: string;
}

/**
 * Detects homoglyph attacks where attackers use similar-looking characters
 * from different Unicode scripts to mimic legitimate domains or keywords
 */
function detectHomoglyphs(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];
    let normalizedText = text;

    // Common homoglyph substitutions
    const homoglyphMap: Record<string, string> = {
        // Latin 'a' lookalikes
        'а': 'a', // Cyrillic 'а'
        'α': 'a', // Greek alpha
        // Latin 'c' lookalikes
        'с': 'c', // Cyrillic 'с'
        // Latin 'e' lookalikes
        'е': 'e', // Cyrillic 'е'
        'ё': 'e', // Cyrillic 'ё'
        'ε': 'e', // Greek epsilon
        // Latin 'o' lookalikes
        'о': 'o', // Cyrillic 'о'
        'ο': 'o', // Greek omicron
        'θ': 'o', // Greek theta (sometimes used)
        // Latin 'p' lookalikes
        'р': 'p', // Cyrillic 'р'
        // Latin 'x' lookalikes
        'х': 'x', // Cyrillic 'х'
        'χ': 'x', // Greek chi
        // Latin 'y' lookalikes
        'у': 'y', // Cyrillic 'у'
        'γ': 'y', // Greek gamma
        // Digit '0' lookalikes
        'Ο': '0', // Greek capital omicron
        'О': '0', // Cyrillic capital O
        // Digit '1' lookalikes
        'Ӏ': '1', // Cyrillic palochka
        'Ⅰ': '1', // Roman numeral I
        // Digit '2' lookalikes
        'ƻ': '2', // Latin letter
        // Digit '3' lookalikes
        'Ʒ': '3', // Latin letter
        // Digit '4' lookalikes
        'Ꮞ': '4', // Cherokee letter
        // Digit '5' lookalikes
        'Ƽ': '5', // Latin letter
        // Digit '6' lookalikes
        'б': '6', // Cyrillic be
        // Digit '8' lookalikes
        'Ȣ': '8', // Latin letter
        '∞': '8', // infinity symbol
        // Digit '9' lookalikes
        'գ': '9', // Armenian letter
    };

    let detected = false;
    let normalized = text;

    // Check for homoglyphs
    for (const [homoglyph, replacement] of Object.entries(homoglyphMap)) {
        if (text.includes(homoglyph)) {
            detected = true;
            techniques.push(`homoglyph-${replacement}`);
            normalized = normalized.split(homoglyph).join(replacement);
        }
    }

    // Also check for mixed script (e.g., Latin + Cyrillic in same word)
    const mixedScriptPattern = /[a-zA-Z].*[\u0400-\u04FF]|[\u0400-\u04FF].*[a-zA-Z]/;
    if (mixedScriptPattern.test(text)) {
        detected = true;
        techniques.push('mixed-script');
    }

    return { detected, techniques, normalizedText: normalized };
}

/**
 * Detects simple leetspeak and symbol substitutions used to hide high-risk words
 * such as v3rify, y0ur, l0gin, pr0file, or upd@te.
 */
function detectLeetspeakObfuscation(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];
    const candidateTokens = [...new Set(
        (text.match(/\b[a-z0-9@-]{2,}\b/gi) || [])
            .filter((token) => /[a-z@]/i.test(token) && /[0134578@]/.test(token)),
    )];

    if (candidateTokens.length === 0) {
        return { detected: false, techniques, normalizedText: text };
    }

    const targetedReplacements: Array<[RegExp, string, string]> = [
        [/upd@te/gi, 'update', 'leet-a'],
        [/p@ssword/gi, 'password', 'leet-a'],
        [/p@sscode/gi, 'passcode', 'leet-a'],
        [/v@lidate/gi, 'validate', 'leet-a'],
        [/upd8/gi, 'update', 'leet-ate'],
        [/2day/gi, 'today', 'leet-two'],
        [/paym3nt/gi, 'payment', 'leet-e'],
        [/re-ent3r/gi, 're-enter', 'leet-e'],
    ];

    const replacements: Array<[RegExp, string, string]> = [
        [/0/g, 'o', 'leet-o'],
        [/1/g, 'i', 'leet-i'],
        [/3/g, 'e', 'leet-e'],
        [/4/g, 'a', 'leet-a'],
        [/5/g, 's', 'leet-s'],
        [/7/g, 't', 'leet-t'],
        [/8/g, 'ate', 'leet-ate'],
    ];

    let normalizedText = text;
    const revealedRiskySignals: string[] = [];
    const riskyTokenPattern = /verify|verification|login|account|profile|update|otp|password|billing|secure|bank|suspension|credentials?|payment|card|identity|confirm|restore|mailbox|sign-?in|access|passcode|pin|send|share|reply|urgent|immediately|avoid|documents?|service|compliance/i;
    const suspiciousPhraseLabels: Array<{ pattern: RegExp; label: string }> = [
        {
            pattern: /\b(?:send|share|reply|provide)\s+(?:your\s+)?(?:otp|pin|passcode|password|credentials?)\b/i,
            label: 'obfuscated-credential-request',
        },
        {
            pattern: /\bverify(?:\s+your)?\s+(?:account|profile|identity|mailbox)\b/i,
            label: 'obfuscated-account-verification',
        },
        {
            pattern: /\b(?:update|secure|restore|reactivate)\s+(?:your\s+)?(?:account|profile|mailbox|login)\b/i,
            label: 'obfuscated-account-update',
        },
        {
            pattern: /\b(?:login|sign-?in)\s+required\b/i,
            label: 'obfuscated-login',
        },
        {
            pattern: /\bavoid\s+(?:suspension|closure|restriction)\b/i,
            label: 'obfuscated-threat',
        },
        {
            pattern: /\bdocuments?\s+required\s+to\s+keep\s+(?:service|access)\b/i,
            label: 'obfuscated-service-documents',
        },
    ];

    for (const token of candidateTokens) {
        let normalizedToken = token;
        const tokenTechniques: string[] = [];

        for (const [pattern, replacement, label] of targetedReplacements) {
            const replaced = normalizedToken.replace(pattern, replacement);
            if (replaced !== normalizedToken) {
                normalizedToken = replaced;
                tokenTechniques.push(label);
            }
        }

        for (const [pattern, replacement, label] of replacements) {
            const replaced = normalizedToken.replace(pattern, replacement);
            if (replaced !== normalizedToken) {
                normalizedToken = replaced;
                tokenTechniques.push(label);
            }
        }

        if (normalizedToken !== token) {
            const escapedToken = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            normalizedText = normalizedText.replace(new RegExp(escapedToken, 'gi'), normalizedToken);

            if (riskyTokenPattern.test(normalizedToken)) {
                techniques.push(...(tokenTechniques.length > 0 ? tokenTechniques : ['leet-normalized']));
                const normalizedLabel = normalizedToken.toLowerCase().replace(/[^a-z]+/g, '-').replace(/^-+|-+$/g, '');
                if (normalizedLabel) {
                    techniques.push(`obfuscated-${normalizedLabel}`);
                    revealedRiskySignals.push(normalizedLabel);
                }
            }
        }
    }

    for (const { pattern, label } of suspiciousPhraseLabels) {
        if (pattern.test(normalizedText)) {
            techniques.push(label);
            revealedRiskySignals.push(label);
        }
    }

    if (revealedRiskySignals.length === 0) {
        return { detected: false, techniques: [], normalizedText: text };
    }

    return {
        detected: true,
        techniques: [...new Set(techniques)],
        normalizedText,
    };
}

/**
 * Detects URL obfuscation techniques
 */
function detectUrlObfuscation(text: string): { detected: boolean; techniques: string[] } {
    const techniques: string[] = [];

    // Check for URL encoding
    const urlEncodedPattern = /%[0-9a-fA-F]{2}/g;
    const urlEncodedMatches = text.match(urlEncodedPattern);
    if (urlEncodedMatches && urlEncodedMatches.length > 3) {
        techniques.push('url-encoding');
    }

    // Check for hex encoding
    const hexEncodedPattern = /\\x[0-9a-fA-F]{2}/g;
    const hexMatches = text.match(hexEncodedPattern);
    if (hexMatches && hexMatches.length > 3) {
        techniques.push('hex-encoding');
    }

    // Check for double encoding
    const doubleEncodedPattern = /%25[0-9a-fA-F]{2}/g;
    const doubleMatches = text.match(doubleEncodedPattern);
    if (doubleMatches && doubleMatches.length > 0) {
        techniques.push('double-encoding');
    }

    // Check for punycode (starts with xn--)
    const punycodePattern = /xn--[a-zA-Z0-9-]+/g;
    const punycodeMatches = text.match(punycodePattern);
    if (punycodeMatches && punycodeMatches.length > 0) {
        techniques.push('punycode');
    }

    return { detected: techniques.length > 0, techniques };
}

/**
 * Detects HTML entity encoding
 */
function detectHtmlEncoding(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];
    let normalizedText = text;

    // Common HTML entities (encoded -> decoded)
    const htmlEntities: Record<string, string> = {
        '&lt;': '<',
        '&gt;': '>',
        '&amp;': '&',
        '&quot;': '"',
        '&#39;': "'",
        '&#x27;': "'",
        '&#x2F;': '/',
        '&#x60;': '`',
        '&#x3D;': '=',
        '&#x25;': '%',
        '&#x40;': '@',
        '&#x24;': '$',
        '&#x23;': '#',
    };

    let detected = false;
    let normalized = text;

    for (const [entity, replacement] of Object.entries(htmlEntities)) {
        if (text.includes(entity)) {
            detected = true;
            techniques.push(`html-entity-${replacement}`);
            normalized = normalized.split(entity).join(replacement);
        }
    }

    // Also check for numeric HTML entities (&#65; or &#x41;)
    const numericEntityPattern = /&#([0-9]+);|&#x([0-9a-fA-F]+);/g;
    const numericMatches = text.match(numericEntityPattern);
    if (numericMatches && numericMatches.length > 3) {
        detected = true;
        techniques.push('numeric-html-entities');
    }

    return { detected, techniques, normalizedText: normalized };
}

/**
 * Detects zero-width and invisible characters
 */
function detectInvisibleChars(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];

    // Zero-width characters
    const zeroWidthPattern = /[\u200B-\u200D\uFEFF\u2060\u180E]/g;
    const zeroWidthMatches = text.match(zeroWidthPattern);
    if (zeroWidthMatches && zeroWidthMatches.length > 0) {
        techniques.push('zero-width-chars');
    }

    // Remove zero-width characters
    const normalizedText = text.replace(zeroWidthPattern, '');

    // Invisible separator characters
    const invisibleSeparators = /[\u2063\u2064\u2062]/g;
    const invisibleMatches = text.match(invisibleSeparators);
    if (invisibleMatches && invisibleMatches.length > 0) {
        techniques.push('invisible-separators');
    }

    // Bidirectional control characters (used for text direction attacks)
    const bidiPattern = /[\u202A-\u202E\u200E\u200F\u061C]/g;
    const bidiMatches = text.match(bidiPattern);
    if (bidiMatches && bidiMatches.length > 0) {
        techniques.push('bidi-control-chars');
    }

    return {
        detected: techniques.length > 0,
        techniques,
        normalizedText: normalizedText.replace(invisibleSeparators, '').replace(bidiPattern, '')
    };
}

/**
 * Detects base64 encoded content in text
 */
function detectBase64(text: string): { detected: boolean; techniques: string[] } {
    const techniques: string[] = [];

    // Require real base64 characteristics so ordinary words/URLs do not trigger.
    const base64Pattern = /\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b/g;
    const base64Matches = text.match(base64Pattern);

    if (base64Matches && base64Matches.length > 0) {
        for (const match of base64Matches) {
            if (match.length < 32 || match.length % 4 !== 0) continue;
            if (!/[+/=]/.test(match)) continue;
            if (/https?|amazon|google|support|billing|payment|account|signin|invoice/i.test(match)) continue;

            try {
                const decoded = Buffer.from(match, 'base64').toString('utf8');
                const printableChars = [...decoded].filter((char) => /[\x09\x0A\x0D\x20-\x7E]/.test(char)).length;
                const printableRatio = decoded.length > 0 ? printableChars / decoded.length : 0;

                if (decoded.length >= 12 && printableRatio >= 0.6) {
                    techniques.push('base64-encoded');
                    break;
                }
            } catch {
                // Ignore invalid base64 candidates.
            }
        }
    }

    return { detected: techniques.length > 0, techniques };
}

/**
 * Detects noise injection (adding benign text to dilute phishing signals)
 */
function detectNoiseInjection(text: string): { detected: boolean; techniques: string[]; normalizedText: string } {
    const techniques: string[] = [];

    // Common noise patterns
    const noisePatterns = [
        // Repeated benign phrases
        /(thank you|regards|sincerely|best regards|kind regards|yours truly)\s*(,\s*)?[a-zA-Z\s]*(\n\s*){2,}/gi,
        // Long disclaimers
        /(this email is confidential|this message is intended only|if you received this email in error).{50,}/gi,
        // Legal boilerplate
        /(copyright|all rights reserved|confidentiality notice|privileged communication).{30,}/gi,
    ];

    let noiseDetected = false;
    let normalizedText = text;

    for (const pattern of noisePatterns) {
        if (pattern.test(text)) {
            noiseDetected = true;
            techniques.push('noise-injection');
            // Remove the noise (simplified - in reality we'd be more careful)
            normalizedText = normalizedText.replace(pattern, ' ');
            break;
        }
    }

    // Check for excessive benign words ratio
    const words = text.toLowerCase().split(/\s+/).filter(w => w.length > 0);
    const benignWords = ['thanks', 'regards', 'hello', 'hi', 'dear', 'sincerely', 'best', 'kind', 'yours', 'truly'];
    const benignCount = words.filter(w => benignWords.includes(w)).length;
    const totalWords = words.length;

    if (totalWords > 50 && benignCount > totalWords * 0.3) {
        // More than 30% of words are benign greetings/closings
        noiseDetected = true;
        techniques.push('excessive-benign-content');
    }

    return { detected: noiseDetected, techniques, normalizedText };
}

/**
 * Main function to detect adversarial attacks in text
 */
export function detectAdversarialAttacks(text: string): AdversarialDetectionResult {
    if (!text || text.trim().length === 0) {
        return {
            detected: false,
            techniques: [],
            confidence: 0,
            normalizedText: text,
            explanation: 'Empty text'
        };
    }

    const allTechniques: string[] = [];
    let normalizedText = text;

    // Run all detectors
    const homoglyphResult = detectHomoglyphs(normalizedText);
    if (homoglyphResult.detected) {
        allTechniques.push(...homoglyphResult.techniques);
        normalizedText = homoglyphResult.normalizedText;
    }

    const leetResult = detectLeetspeakObfuscation(normalizedText);
    if (leetResult.detected) {
        allTechniques.push(...leetResult.techniques);
        normalizedText = leetResult.normalizedText;
    }

    const urlObfuscationResult = detectUrlObfuscation(normalizedText);
    if (urlObfuscationResult.detected) {
        allTechniques.push(...urlObfuscationResult.techniques);
    }

    const htmlEncodingResult = detectHtmlEncoding(normalizedText);
    if (htmlEncodingResult.detected) {
        allTechniques.push(...htmlEncodingResult.techniques);
        normalizedText = htmlEncodingResult.normalizedText;
    }

    const invisibleCharsResult = detectInvisibleChars(normalizedText);
    if (invisibleCharsResult.detected) {
        allTechniques.push(...invisibleCharsResult.techniques);
        normalizedText = invisibleCharsResult.normalizedText;
    }

    const base64Result = detectBase64(normalizedText);
    if (base64Result.detected) {
        allTechniques.push(...base64Result.techniques);
    }

    const noiseResult = detectNoiseInjection(normalizedText);
    if (noiseResult.detected) {
        allTechniques.push(...noiseResult.techniques);
        normalizedText = noiseResult.normalizedText;
    }

    // Calculate confidence based on number and severity of techniques
    const confidence = Math.min(100, allTechniques.length * 15);

    // Generate explanation
    let explanation = 'No adversarial techniques detected.';
    if (allTechniques.length > 0) {
        const uniqueTechniques = [...new Set(allTechniques)];
        explanation = `Detected ${uniqueTechniques.length} adversarial technique(s): ${uniqueTechniques.join(', ')}.`;
    }

    logger.debug('Adversarial attack detection completed', {
        techniques: allTechniques,
        confidence,
        originalLength: text.length,
        normalizedLength: normalizedText.length
    });

    return {
        detected: allTechniques.length > 0,
        techniques: allTechniques,
        confidence,
        normalizedText,
        explanation
    };
}

/**
 * Preprocess text by removing adversarial artifacts before analysis
 * This should be called before running phishing detection
 */
export function preprocessAdversarialText(text: string): string {
    const result = detectAdversarialAttacks(text);
    return result.normalizedText;
}