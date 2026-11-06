"""Transparent keyword/phrase extraction. This is not machine learning."""
import re

GROUPS = {
    "Who is contacting you?": {
        "claims_bank": "Claims to be from a bank",
        "claims_government": "Claims to be government (BISP, FBR, police, FIA)",
        "claims_telecom": "Claims to be a telecom company",
        "claims_courier": "Claims to be a courier or parcel service",
        "unknown_sender": "Unknown sender or number",
        "personal_number_used": "Official-looking message from a personal number",
    },
    "What do they ask for?": {
        "asks_otp": "Asks for OTP or verification code",
        "asks_pin": "Asks for PIN or password",
        "asks_card_details": "Asks for card number or CVV",
        "card_activation_request": "Mentions activating a credit or debit card",
        "asks_cnic": "Asks for CNIC details",
        "asks_advance_fee": "Asks for an advance fee, tax or charges",
        "asks_wallet_transfer": "Asks for wallet transfer",
        "wrong_transfer_claim": "Claims money was sent by mistake",
        "asks_install_app": "Asks you to install an app",
        "asks_remote_access": "Asks for remote access",
    },
    "How does the message look?": {
        "urgent_threat": "Urgent threat or deadline",
        "asks_secrecy": "Asks you to keep it secret",
        "emotional_request": "Emotional emergency story",
        "suspicious_link": "Contains a suspicious link",
        "shortened_link": "Contains a shortened link",
        "fake_domain": "Website resembles a genuine domain",
        "spelling_errors": "Spelling or grammar mistakes",
    },
    "What do they offer?": {
        "prize_lottery": "Prize, lottery or cash reward",
        "guaranteed_returns": "Guaranteed investment returns",
        "too_good_salary": "Unrealistically high salary",
        "marketplace_deal": "Marketplace buying or selling",
        "romance_contact": "Online romantic contact",
    },
}
FLAGS = [f for group in GROUPS.values() for f in group]
CHANNELS = ["call", "sms", "whatsapp", "email", "social_media", "in_person"]
PRESETS = {
    "📞 Bank OTP call": {"flags":["claims_bank","asks_otp","urgent_threat","unknown_sender"],"channel":"call"},
    "💬 BISP prize SMS": {"flags":["claims_government","prize_lottery","asks_cnic","suspicious_link"],"channel":"sms"},
    "💼 WhatsApp job offer": {"flags":["too_good_salary","asks_advance_fee","unknown_sender"],"channel":"whatsapp"},
    "🛒 Marketplace buyer": {"flags":["marketplace_deal","asks_otp","suspicious_link"],"channel":"whatsapp"},
}

PATTERNS = {
    "claims_bank": [r"\b(bank|hbl|ubl|mcb|meezan|alfalah|askar[iy])\b"],
    "claims_government": [r"\b(bisp|ehsaas|fbr|fia|police|government|govt)\b"],
    "claims_telecom": [r"\b(jazz|zong|telenor|ufone|telecom)\b"],
    "claims_courier": [r"\b(courier|parcel|delivery|shipment|tcs|leopard)\b"],
    "asks_otp": [r"\b(otp|one.time password|verification code)\b"],
    "asks_pin": [r"\b(pin|password|passcode)\b"],
    "asks_card_details": [r"\b(cvv|card number|credit card|debit card)\b"],
    "card_activation_request": [r"\b(?:activate|activation|activating)\b.{0,35}\b(?:credit|debit|bank) card\b", r"\b(?:credit|debit|bank) card\b.{0,35}\b(?:activate|activation|activating)\b"],
    "asks_cnic": [r"\b(cnic|identity card|national identity)\b"],
    "asks_advance_fee": [r"\b(advance fee|processing fee|registration fee|tax|charges|pay first)\b", r"\b(?:pay|send|give)\s+(?:rs\.?\s*)?[\d,]+\s+(?:rupees\s+)?(?:to\s+)?(?:activate|activation)\b", r"\b(?:ask(?:ing)?|request(?:ing)?)\s+for\s+(?:rs\.?\s*)?[\d,]+\s+(?:rupees\s+)?(?:to\s+)?(?:activate|activation)\b", r"\bfee of\s+(?:rs\.?\s*)?[\d,]+\b"],    
    "asks_wallet_transfer": [r"\b(jazzcash|easypaisa|wallet transfer|send money)\b"],
    "wrong_transfer_claim": [r"\b(sent .* by mistake|mistaken transfer|wrong transfer|money sent accidentally)\b"],
    "asks_install_app": [r"\b(install .* app|download .* app|apk)\b"],
    "asks_remote_access": [r"\b(anydesk|teamviewer|remote access|screen sharing)\b"],
    "urgent_threat": [r"\b(immediately|urgent|blocked|suspended|arrest|within \d+ hours|last warning)\b"],
    "asks_secrecy": [r"\b(keep .* secret|don't tell|do not tell|confidential)\b"],
    "emotional_request": [r"\b(emergency|accident|hospital|relative in trouble|help me urgently)\b"],
    "suspicious_link": [r"https?://|www\."],
    "shortened_link": [r"\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)\b"],
    "fake_domain": [r"\b(login|verify|secure|account).{0,20}\.(com|net|pk)\b"],
    "spelling_errors": [r"\b(kindly revert|dear customer|congratulation you|you has won)\b"],
    "prize_lottery": [r"\b(prize|lottery|won|winner|cash reward|claim reward)\b"],
    "guaranteed_returns": [r"\b(guaranteed return|double your money|risk.free profit|fixed profit)\b"],
    "too_good_salary": [r"\b(high salary|earn \d+|work from home|daily income)\b"],
    "marketplace_deal": [r"\b(olx|marketplace|buyer|seller|daraz)\b"],
    "romance_contact": [r"\b(love you|relationship|romantic|marriage proposal)\b"],
    "unknown_sender": [r"\b(unknown number|don't know this number|stranger)\b"],
    "personal_number_used": [r"\b(personal number|private number|whatsapp number)\b"],
}

def analyze_message(message: str) -> dict:
    """Return matched flags and the phrase that triggered each flag."""
    text = message.lower()
    found, evidence = [], {}
    for flag, patterns in PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                found.append(flag)
                evidence[flag] = match.group(0)
                break
    return {"flags": found, "evidence": evidence}
