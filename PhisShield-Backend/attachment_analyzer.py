"""
PhishShield Attachment Content Analyzer
=======================================
Extracts and analyzes text from email attachments (PDF, HTML, DOCX).
Detects credential harvesting, hidden links, phishing URLs, and suspicious forms.

This module is designed for production use — all parsers are lazily imported
and wrapped in try/except so the system degrades gracefully when optional
dependencies are missing.
"""

from __future__ import annotations

import base64
import io
import re
import logging
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("phishshield.attachments")

# ---------------------------------------------------------------------------
# Credential Harvesting / Phishing patterns for attachment content
# ---------------------------------------------------------------------------

CREDENTIAL_HARVEST_PATTERNS = [
    re.compile(
        r"\b(enter\s+your\s*(password|passcode|pin|credentials?|username))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(verify\s+your\s*(account|identity|credentials?|email|password))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(confirm\s+your\s*(password|account|identity|login|details))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(log\s*in\s+to\s+(?:confirm|verify|update|secure)\s+your\s+account)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(update\s+your\s*(?:billing|payment|bank)\s*(?:info|information|details))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(share\s+your\s*(?:otp|pin|password|passcode|cvv|ssn))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(your\s+account\s+(?:has\s+been\s+)?(?:suspended|locked|restricted|compromised))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(unauthorized\s+(?:access|activity|login)\s+detected)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(click\s+(?:here|below)\s+to\s+(?:verify|confirm|restore|reactivate|unlock))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(seed\s+phrase|private\s+key|wallet\s+recovery)\b",
        re.IGNORECASE,
    ),
]

FORM_ACTION_PATTERN = re.compile(
    r"""<form[^>]*action\s*=\s*["']?(https?://[^"'\s>]+)""",
    re.IGNORECASE,
)

FORM_INPUT_PATTERN = re.compile(
    r"""<input[^>]*(?:type\s*=\s*["']?(?:password|text|email|tel|hidden)["']?)[^>]*(?:name\s*=\s*["']?(?:password|pass|pwd|passwd|login|user|email|otp|pin|cvv|ssn|card)["']?)""",
    re.IGNORECASE,
)

PHISHING_URL_PATTERN = re.compile(
    r"https?://\S*(?:verify|login|secure|update|confirm|account|password|otp|suspend|claim|reward|kyc|auth)\S*",
    re.IGNORECASE,
)

HIDDEN_LINK_PATTERN = re.compile(
    r"""<a[^>]*href\s*=\s*["'](https?://[^"']+)["'][^>]*>([^<]+)</a>""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Text extraction: PDF
# ---------------------------------------------------------------------------

def extract_text_from_pdf(data: bytes) -> str:
    """Extract text from PDF bytes using pdfplumber (preferred) or PyMuPDF fallback."""
    text = ""

    # Try pdfplumber first
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for page in pdf.pages[:20]:  # Cap at 20 pages for performance
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        if text.strip():
            return text.strip()
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("pdfplumber failed: %s", exc)

    # Fallback to PyMuPDF (fitz)
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=data, filetype="pdf")
        for page_num in range(min(doc.page_count, 20)):
            page = doc.load_page(page_num)
            page_text = page.get_text()
            if page_text:
                text += page_text + "\n"
        doc.close()
        if text.strip():
            return text.strip()
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("PyMuPDF failed: %s", exc)

    return text.strip()


# ---------------------------------------------------------------------------
# Text extraction: HTML
# ---------------------------------------------------------------------------

class _HTMLTextExtractor(HTMLParser):
    """Strip HTML tags and extract visible text + link destinations."""

    def __init__(self) -> None:
        super().__init__()
        self._text_chunks: list[str] = []
        self._links: list[tuple[str, str]] = []  # (href, visible_text)
        self._form_actions: list[str] = []
        self._form_inputs: list[str] = []
        self._current_link_href: str | None = None
        self._current_link_text: list[str] = []
        self._skip_tags = {"script", "style", "noscript"}
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: (v or "") for k, v in attrs}
        if tag in self._skip_tags:
            self._skip_depth += 1
            return
        if tag == "a":
            self._current_link_href = attr_dict.get("href", "")
            self._current_link_text = []
        if tag == "form":
            action = attr_dict.get("action", "")
            if action:
                self._form_actions.append(action)
        if tag == "input":
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "").lower()
            if input_type in ("password", "text", "email", "tel", "hidden"):
                if input_name in ("password", "pass", "pwd", "passwd", "login", "user",
                                  "email", "otp", "pin", "cvv", "ssn", "card",
                                  "username", "passcode"):
                    self._form_inputs.append(input_name)

    def handle_endtag(self, tag: str) -> None:
        if tag in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if tag == "a" and self._current_link_href is not None:
            visible = " ".join(self._current_link_text).strip()
            self._links.append((self._current_link_href, visible))
            self._current_link_href = None
            self._current_link_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        self._text_chunks.append(data)
        if self._current_link_href is not None:
            self._current_link_text.append(data)

    @property
    def text(self) -> str:
        return " ".join(self._text_chunks)

    @property
    def links(self) -> list[tuple[str, str]]:
        return self._links

    @property
    def form_actions(self) -> list[str]:
        return self._form_actions

    @property
    def form_inputs(self) -> list[str]:
        return self._form_inputs


def extract_text_from_html(data: bytes | str) -> dict[str, Any]:
    """Parse HTML attachment: extract text, links, forms."""
    html_str = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html_str)
    except Exception as exc:
        logger.debug("HTML parsing error: %s", exc)

    return {
        "text": parser.text.strip(),
        "links": parser.links,
        "form_actions": parser.form_actions,
        "form_inputs": parser.form_inputs,
        "raw_html": html_str,
    }


# ---------------------------------------------------------------------------
# Text extraction: DOCX
# ---------------------------------------------------------------------------

def extract_text_from_docx(data: bytes) -> str:
    """Extract text from DOCX bytes using python-docx."""
    try:
        from docx import Document
        doc = Document(io.BytesIO(data))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(paragraphs)
    except ImportError:
        logger.debug("python-docx not installed; DOCX extraction unavailable")
        return ""
    except Exception as exc:
        logger.debug("DOCX extraction failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Link mismatch detection
# ---------------------------------------------------------------------------

def detect_hidden_link_mismatches(links: list[tuple[str, str]]) -> list[dict[str, str]]:
    """Detect links where visible text shows one domain but href points elsewhere.
    
    Example: visible="www.paypal.com" but href="http://evil-site.com/phish"
    """
    mismatches: list[dict[str, str]] = []
    for href, visible_text in links:
        if not href or not visible_text:
            continue
        # Check if visible text looks like a URL/domain
        visible_url_match = re.search(
            r"(?:https?://)?([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}",
            visible_text,
            re.IGNORECASE,
        )
        if not visible_url_match:
            continue

        visible_domain = visible_url_match.group(0).lower()
        visible_domain = re.sub(r"^https?://", "", visible_domain).split("/")[0]

        try:
            href_parsed = urlparse(href)
            href_domain = (href_parsed.hostname or "").lower()
        except Exception:
            continue

        if not href_domain:
            continue

        # Strip www. for comparison
        vis_clean = visible_domain.lstrip("www.")
        href_clean = href_domain.lstrip("www.")

        if vis_clean and href_clean and vis_clean != href_clean:
            # Check if one is a subdomain of the other
            if not (href_clean.endswith(f".{vis_clean}") or vis_clean.endswith(f".{href_clean}")):
                mismatches.append({
                    "visible_text": visible_text.strip(),
                    "visible_domain": visible_domain,
                    "actual_href": href,
                    "actual_domain": href_domain,
                })
    return mismatches


# ---------------------------------------------------------------------------
# Main attachment content analyzer
# ---------------------------------------------------------------------------

def analyze_attachment_content(
    attachments: list[dict[str, Any]] | None,
    email_text: str,
    *,
    sender_domain: str = "",
    trusted_sender: bool = False,
) -> dict[str, Any]:
    """
    Deep-analyze attachment contents for phishing indicators.
    
    Processes PDF, HTML, DOCX attachments by extracting text and checking for:
    - Credential harvesting phrases
    - Hidden link mismatches (display domain != actual domain)
    - Suspicious form actions
    - Phishing URLs embedded in content
    
    Returns dict with signals, score_bonus, and per-attachment findings.
    """
    if not attachments:
        return {"signals": [], "score_bonus": 0, "findings": [], "extracted_texts": {}}

    signals: list[str] = []
    findings: list[dict[str, Any]] = []
    score_bonus = 0
    extracted_texts: dict[str, str] = {}

    for attachment in attachments:
        filename = str(attachment.get("filename") or "unknown").strip()
        content_type = str(attachment.get("contentType") or "").lower()
        ext = Path(filename).suffix.lower()
        is_password_protected = bool(attachment.get("isPasswordProtected", False))

        # Get raw content — either from base64-encoded data or extractedText
        raw_data: bytes | None = None
        extracted_text = str(attachment.get("extractedText") or "").strip()

        # If base64 content is provided, decode it
        b64_content = attachment.get("content") or attachment.get("data") or attachment.get("base64")
        if b64_content and isinstance(b64_content, str):
            try:
                raw_data = base64.b64decode(b64_content)
            except Exception:
                pass

        # --- Extract text based on file type ---
        attachment_finding: dict[str, Any] = {
            "filename": filename,
            "type": ext or content_type,
            "signals": [],
            "risk": "low",
        }

        if not is_password_protected:
            # PDF extraction
            if ext == ".pdf" or "pdf" in content_type:
                if raw_data:
                    pdf_text = extract_text_from_pdf(raw_data)
                    if pdf_text:
                        extracted_text = (extracted_text + "\n" + pdf_text).strip()
                        extracted_texts[filename] = extracted_text

            # HTML extraction
            elif ext in (".html", ".htm") or "html" in content_type:
                html_data = raw_data or extracted_text.encode("utf-8")
                if html_data:
                    html_result = extract_text_from_html(html_data)
                    html_text = html_result["text"]
                    if html_text:
                        extracted_text = (extracted_text + "\n" + html_text).strip()
                        extracted_texts[filename] = extracted_text

                    # Check link mismatches
                    mismatches = detect_hidden_link_mismatches(html_result["links"])
                    if mismatches:
                        sig = "Hidden link mismatch in attachment"
                        if sig not in signals:
                            signals.append(sig)
                        attachment_finding["signals"].append(sig)
                        attachment_finding["link_mismatches"] = mismatches
                        score_bonus += min(len(mismatches) * 12, 25)
                        attachment_finding["risk"] = "high"

                    # Check form actions for external phishing domains
                    for action_url in html_result["form_actions"]:
                        try:
                            action_host = urlparse(action_url).hostname or ""
                            action_host = action_host.lower().strip(".")
                            if action_host and sender_domain:
                                sender_root = sender_domain.split(".")[-2] if len(sender_domain.split(".")) >= 2 else sender_domain
                                if sender_root not in action_host:
                                    sig = "Suspicious form target in attachment"
                                    if sig not in signals:
                                        signals.append(sig)
                                    attachment_finding["signals"].append(sig)
                                    score_bonus += 15
                                    attachment_finding["risk"] = "high"
                        except Exception:
                            pass

                    # Check for credential-harvesting form inputs
                    if html_result["form_inputs"]:
                        sig = "Credential harvesting form in attachment"
                        if sig not in signals:
                            signals.append(sig)
                        attachment_finding["signals"].append(sig)
                        score_bonus += 18
                        attachment_finding["risk"] = "high"

            # DOCX extraction
            elif ext in (".docx", ".doc") or "wordprocessingml" in content_type:
                if raw_data:
                    docx_text = extract_text_from_docx(raw_data)
                    if docx_text:
                        extracted_text = (extracted_text + "\n" + docx_text).strip()
                        extracted_texts[filename] = extracted_text

        # --- Analyze extracted text for phishing indicators ---
        if extracted_text:
            # Credential harvesting detection
            harvest_count = sum(
                1 for p in CREDENTIAL_HARVEST_PATTERNS if p.search(extracted_text)
            )
            if harvest_count >= 2:
                sig = "Credential harvesting in attachment"
                if sig not in signals:
                    signals.append(sig)
                attachment_finding["signals"].append(sig)
                score_bonus += 20
                attachment_finding["risk"] = "high"
            elif harvest_count == 1 and not trusted_sender:
                sig = "Suspicious credential request in attachment"
                if sig not in signals:
                    signals.append(sig)
                attachment_finding["signals"].append(sig)
                score_bonus += 10
                attachment_finding["risk"] = "medium"

            # Phishing URLs in attachment text
            phishing_urls = PHISHING_URL_PATTERN.findall(extracted_text)
            if phishing_urls and not trusted_sender:
                sig = "Malicious content in attachment"
                if sig not in signals:
                    signals.append(sig)
                attachment_finding["signals"].append(sig)
                score_bonus += 15
                attachment_finding["risk"] = "high"

            # Hidden link mismatch detection in raw text (for non-HTML that may have inline HTML)
            if ext not in (".html", ".htm"):
                raw_link_matches = HIDDEN_LINK_PATTERN.findall(extracted_text)
                if raw_link_matches:
                    mismatches = detect_hidden_link_mismatches(raw_link_matches)
                    if mismatches:
                        sig = "Hidden link mismatch in attachment"
                        if sig not in signals:
                            signals.append(sig)
                        attachment_finding["signals"].append(sig)
                        score_bonus += 15
                        attachment_finding["risk"] = "high"

        findings.append(attachment_finding)

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 45),  # Cap to prevent FP over-inflation
        "findings": findings,
        "extracted_texts": extracted_texts,
    }
