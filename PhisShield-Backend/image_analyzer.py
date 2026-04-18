"""
PhishShield Image & QR Code Phishing Analyzer
==============================================
Detects phishing content embedded in images via OCR (pytesseract)
and QR code scanning (pyzbar or opencv).

All dependencies are optional — the system degrades gracefully and
returns empty results when OCR/QR libraries are unavailable.
"""

from __future__ import annotations

import io
import base64
import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("phishshield.image_analyzer")

# ---------------------------------------------------------------------------
# Phishing patterns for OCR-extracted text from images
# ---------------------------------------------------------------------------

IMAGE_PHISHING_PATTERNS = [
    re.compile(
        r"\b(enter\s+your\s*(?:password|pin|otp|passcode|credentials?))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(verify\s+your\s*(?:account|identity|email|details))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(your\s+account\s+(?:has\s+been\s+)?(?:suspended|locked|restricted|disabled))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(click\s+(?:here|below)\s+to\s+(?:verify|confirm|unlock|restore))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(unauthorized\s+(?:access|login|activity)\s+detected)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(scan\s+(?:this\s+)?(?:qr|code)\s+to\s+(?:verify|login|confirm|pay|proceed))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(urgent\s*:\s*(?:update|verify|confirm)\s+your\s+(?:account|password|details))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(login\s+to\s+your\s+(?:bank|paypal|account|wallet))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(share\s+(?:your\s+)?(?:otp|pin|password|cvv|ssn))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(seed\s+phrase|private\s+key|wallet\s+recovery)\b",
        re.IGNORECASE,
    ),
]

# Known suspicious domains that appear in QR codes
SUSPICIOUS_QR_DOMAINS = re.compile(
    r"\b(?:bit\.ly|tinyurl\.com|rb\.gy|t\.co|is\.gd|shorturl\.at|cutt\.ly|ow\.ly)\b",
    re.IGNORECASE,
)

# QR target patterns that suggest phishing
PHISHING_QR_URL_PATTERN = re.compile(
    r"https?://\S*(?:verify|login|secure|update|confirm|account|password|otp|auth|payment|kyc)\S*",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# OCR: Extract text from image
# ---------------------------------------------------------------------------

def _ocr_extract_text(image_data: bytes) -> str:
    """Extract text from image bytes using pytesseract + PIL."""
    try:
        from PIL import Image
        import pytesseract
    except ImportError:
        logger.debug("pytesseract or PIL not installed; OCR unavailable")
        return ""

    try:
        image = Image.open(io.BytesIO(image_data))
        # Convert to RGB if needed (handles RGBA, grayscale, etc.)
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        # Resize very large images to prevent slow OCR
        max_dim = 2000
        if max(image.size) > max_dim:
            ratio = max_dim / max(image.size)
            new_size = (int(image.width * ratio), int(image.height * ratio))
            image = image.resize(new_size)
        text = pytesseract.image_to_string(image, timeout=10)
        return text.strip()
    except Exception as exc:
        logger.debug("OCR extraction failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# QR Code: Decode QR codes from image
# ---------------------------------------------------------------------------

def _decode_qr_codes(image_data: bytes) -> list[str]:
    """Decode QR codes from image bytes using pyzbar (preferred) or opencv."""
    decoded_urls: list[str] = []

    # Try pyzbar first
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as pyzbar_decode

        image = Image.open(io.BytesIO(image_data))
        results = pyzbar_decode(image)
        for result in results:
            data = result.data.decode("utf-8", errors="ignore").strip()
            if data:
                decoded_urls.append(data)
        if decoded_urls:
            return decoded_urls
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("pyzbar QR decoding failed: %s", exc)

    # Fallback to opencv
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(image_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is not None:
            detector = cv2.QRCodeDetector()
            retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(img)
            if retval and decoded_info:
                for data in decoded_info:
                    data = data.strip()
                    if data:
                        decoded_urls.append(data)
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("OpenCV QR decoding failed: %s", exc)

    return decoded_urls


# ---------------------------------------------------------------------------
# Analyze QR URL safety
# ---------------------------------------------------------------------------

def _analyze_qr_url(url: str, sender_domain: str = "") -> dict[str, Any]:
    """Analyze a decoded QR URL for phishing indicators."""
    result: dict[str, Any] = {
        "url": url,
        "is_suspicious": False,
        "reasons": [],
    }

    # Not a URL — might be plain text
    if not url.startswith(("http://", "https://")):
        # Could be a phone number, plain text, or non-URL data
        if re.search(r"\b(verify|login|password|otp|account|suspended)\b", url, re.IGNORECASE):
            result["is_suspicious"] = True
            result["reasons"].append("QR contains phishing keywords")
        return result

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip(".")
    except Exception:
        result["is_suspicious"] = True
        result["reasons"].append("Malformed QR URL")
        return result

    # Check for URL shorteners
    if SUSPICIOUS_QR_DOMAINS.search(host):
        result["is_suspicious"] = True
        result["reasons"].append("QR redirects through URL shortener")

    # Check for phishing URL patterns
    if PHISHING_QR_URL_PATTERN.search(url):
        result["is_suspicious"] = True
        result["reasons"].append("QR URL contains phishing keywords")

    # Domain mismatch with sender
    if sender_domain and host:
        sender_root = sender_domain.split(".")[-2] if len(sender_domain.split(".")) >= 2 else sender_domain
        if sender_root and sender_root not in host:
            result["is_suspicious"] = True
            result["reasons"].append("QR domain does not match sender")

    # Check for IP address URLs
    try:
        import ipaddress
        # If host is an IP address, it's suspicious
        host_clean = host.strip("[]")
        ipaddress.ip_address(host_clean)
        result["is_suspicious"] = True
        result["reasons"].append("QR points to IP address instead of domain")
    except (ValueError, ImportError):
        pass

    return result


# ---------------------------------------------------------------------------
# Main image phishing analyzer
# ---------------------------------------------------------------------------

def analyze_image_content(
    attachments: list[dict[str, Any]] | None,
    email_text: str,
    *,
    sender_domain: str = "",
    trusted_sender: bool = False,
) -> dict[str, Any]:
    """
    Analyze image attachments for phishing content via OCR and QR decoding.
    
    Processes PNG, JPG, GIF, BMP, TIFF images to detect:
    - Phishing text rendered as images (OCR bypass)
    - QR codes leading to malicious URLs
    - OTP/credential requests embedded in images
    
    Returns dict with signals, score_bonus, and per-image findings.
    """
    if not attachments:
        return {"signals": [], "score_bonus": 0, "findings": []}

    IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp"}
    IMAGE_MIMETYPES = {"image/png", "image/jpeg", "image/gif", "image/bmp", "image/tiff", "image/webp"}

    signals: list[str] = []
    findings: list[dict[str, Any]] = []
    score_bonus = 0

    for attachment in attachments:
        filename = str(attachment.get("filename") or "unknown").strip()
        content_type = str(attachment.get("contentType") or "").lower()
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        is_image = ext in IMAGE_EXTENSIONS or content_type in IMAGE_MIMETYPES
        if not is_image:
            continue

        # Get raw image data
        image_data: bytes | None = None
        b64_content = attachment.get("content") or attachment.get("data") or attachment.get("base64")
        if b64_content and isinstance(b64_content, str):
            try:
                image_data = base64.b64decode(b64_content)
            except Exception:
                continue

        if not image_data:
            # If pre-flagged QR code by extension
            if attachment.get("hasQrCode"):
                sig = "Suspicious QR redirect"
                if sig not in signals:
                    signals.append(sig)
                score_bonus += 15
            continue

        image_finding: dict[str, Any] = {
            "filename": filename,
            "type": "image",
            "ocr_text": "",
            "qr_urls": [],
            "signals": [],
            "risk": "low",
        }

        # --- OCR Analysis ---
        ocr_text = _ocr_extract_text(image_data)
        if ocr_text:
            image_finding["ocr_text"] = ocr_text[:500]  # Cap for response size

            # Check OCR text for phishing patterns
            phish_hits = sum(
                1 for p in IMAGE_PHISHING_PATTERNS if p.search(ocr_text)
            )
            if phish_hits >= 2:
                sig = "Phishing text detected in image"
                if sig not in signals:
                    signals.append(sig)
                image_finding["signals"].append(sig)
                score_bonus += 22
                image_finding["risk"] = "high"
            elif phish_hits == 1 and not trusted_sender:
                sig = "Suspicious text in image attachment"
                if sig not in signals:
                    signals.append(sig)
                image_finding["signals"].append(sig)
                score_bonus += 10
                image_finding["risk"] = "medium"

        # --- QR Code Analysis ---
        qr_urls = _decode_qr_codes(image_data)
        if qr_urls:
            image_finding["qr_urls"] = qr_urls[:5]  # Cap
            for qr_url in qr_urls[:3]:
                qr_analysis = _analyze_qr_url(qr_url, sender_domain)
                if qr_analysis["is_suspicious"]:
                    sig = "Suspicious QR redirect"
                    if sig not in signals:
                        signals.append(sig)
                    image_finding["signals"].extend(qr_analysis["reasons"])
                    score_bonus += 18
                    image_finding["risk"] = "high"

        findings.append(image_finding)

    return {
        "signals": signals,
        "score_bonus": min(score_bonus, 40),  # Cap to prevent FP inflation
        "findings": findings,
    }
