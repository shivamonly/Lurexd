from __future__ import annotations

import re
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATABASE_PATH = BASE_DIR / "data" / "phishshield.db"

SIMULATION_STATUS_ORDER = {"Sent": 0, "Opened": 1, "Clicked": 2, "Compromised": 3}

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
URL_PATTERN = re.compile(r"(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+)", re.IGNORECASE)
IP_HOST_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

TRANSPARENT_PIXEL_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)

PHISHING_TEMPLATES = {
    "microsoft_reset": {
        "title": "Urgent Microsoft Reset",
        "subject": "Action required: password reset pending",
        "preview": "A familiar enterprise password reset notice with local-only tracking links.",
        "accent": "blue",
    },
    "netflix_billing": {
        "title": "Netflix Billing Failure",
        "subject": "Your subscription payment could not be processed",
        "preview": "Consumer billing pressure pattern for awareness training.",
        "accent": "red",
    },
    "payroll_update": {
        "title": "Payroll Deposit Update",
        "subject": "Confirm direct deposit details before payroll cutoff",
        "preview": "Finance-themed lure using urgency and sensitive-data language.",
        "accent": "yellow",
    },
    "shipping_notice": {
        "title": "Missed Delivery Notice",
        "subject": "Delivery exception: address confirmation needed",
        "preview": "Parcel-style notification with a dummy redirect for local education.",
        "accent": "green",
    },
}

LEXICAL_RULES = [
    (
        "Urgency Keywords Found",
        re.compile(r"\b(urgent|immediate|within\s+24\s+hours|act\s+now|final\s+notice|expires?\s+today)\b", re.I),
        11,
    ),
    (
        "Account Pressure Language",
        re.compile(r"\b(account\s+(suspended|locked|terminated)|verify\s+your\s+identity|unusual\s+activity|security\s+alert)\b", re.I),
        13,
    ),
    (
        "Financial Coercion Terms",
        re.compile(r"\b(wire\s+transfer|invoice|payment\s+failed|billing\s+failure|direct\s+deposit|refund|gift\s+card)\b", re.I),
        12,
    ),
    (
        "Credential Request Language",
        re.compile(r"\b(password|login|sign\s*in|credentials?|one[-\s]?time\s+code|mfa|2fa)\b", re.I),
        10,
    ),
    (
        "Attachment Bait",
        re.compile(r"\b(invoice|statement|document|secure\s+message|shared\s+file).{0,30}\b(attached|download|open)\b", re.I),
        9,
    ),
]

SUSPICIOUS_TOP_LEVEL_DOMAINS = {"zip", "top", "click", "xyz", "tk", "ru", "rest", "support", "country", "gq"}
URL_SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}

BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "paypal": {"paypal.com"},
    "netflix": {"netflix.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
}

BRAND_NAMES = sorted(BRAND_DOMAINS)
LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
