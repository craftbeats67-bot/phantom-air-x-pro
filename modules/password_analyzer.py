"""MODULE 08 - Local password strength analyzer. The password never leaves memory: no network, no logging, no storage."""
import math, re, string

COMMON = {"password", "12345678", "123456789", "1234567890", "qwerty123", "iloveyou", "admin123", "welcome1", "letmein1", "password1", "password123",
          "qwertyuiop", "11111111", "00000000", "abcd1234", "india123", "india@123", "admin@123", "wifi1234", "internet", "12341234", "987654321",
          "football", "monkey123", "dragon123", "sunshine", "princess", "whatever", "trustno1", "changeme", "default1", "router123", "airtel123", "jio12345"}
WALKS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0987654321", "abcdefghijklmnopqrstuvwxyz"]

def pool_size(pw):
    return sum(n for ok, n in ((re.search("[a-z]", pw), 26), (re.search("[A-Z]", pw), 26), (re.search(r"\d", pw), 10),
                               (re.search(r"[^\w\s]", pw), 32), (re.search(r"\s", pw), 1)) if ok)

def has_sequence(pw, n=4):
    low = pw.lower()
    return any(w[i:i + n] in low or w[::-1][i:i + n] in low for w in WALKS for i in range(len(w) - n + 1))

def analyze(pw):
    issues, recs = [], []
    length, pool = len(pw), pool_size(pw)
    entropy = round(length * math.log2(pool), 1) if pool else 0.0
    low = pw.lower()
    if length < 8: issues.append("Shorter than 8 characters: not allowed for WPA2/WPA3 Wi-Fi passphrases.")
    elif length < 12: issues.append("Under 12 characters: weak against offline guessing.")
    if low in COMMON or re.sub(r"[\d\W_]+$", "", low) in COMMON: issues.append("Matches a very common password.")
    if has_sequence(pw): issues.append("Contains a keyboard or alphabet/number sequence.")
    if re.search(r"(.)\1{2,}", pw): issues.append("Contains 3+ repeated characters in a row.")
    if re.search(r"(19|20)\d{2}", pw): issues.append("Contains a year (easy to guess).")
    if len(set(pw)) < max(4, length // 3): issues.append("Very few unique characters.")
    classes = sum(bool(re.search(p, pw)) for p in ("[a-z]", "[A-Z]", r"\d", r"[^\w\s]"))
    if classes < 3 and length < 16: issues.append("Uses fewer than 3 character types.")
    penalty = 12 * len([i for i in issues if not i.startswith("Under") and not i.startswith("Shorter")])
    score = max(0, min(100, int(entropy * 1.1) - penalty - (30 if length < 8 else 10 if length < 12 else 0)))
    rating = "Very weak" if score < 25 else "Weak" if score < 45 else "Fair" if score < 65 else "Strong" if score < 85 else "Very strong"
    recs += ["Use a passphrase of 4+ random words (16+ characters), e.g. from a password manager's generator.",
             "Use a different Wi-Fi password from every other account.", "Change it if it was ever shared widely or the router is second-hand."]
    if length >= 63: issues.append("WPA2/WPA3 passphrases are limited to 63 characters.")
    return {"length": length, "classes": classes, "entropy_bits": entropy, "score": score, "rating": rating, "issues": issues, "recommendations": recs}

def run():
    import getpass
    from core import config, terminal_ui as ui
    ui.header("08 · PASSWORD SECURITY ANALYZER")
    ui.info("Analysis happens only on this device. The password is not saved, logged or uploaded.")
    pw = getpass.getpass("  Enter Wi-Fi password to test (hidden): ")
    if not pw: ui.warn("Nothing entered."); return
    r = analyze(pw); del pw
    ui.table("Result", ["Check", "Value"], [["Length", r["length"]], ["Character types (of 4)", r["classes"]], ["Estimated entropy", f"{r['entropy_bits']} bits (upper bound)"],
                                           ["Score", f"{r['score']}/100"], ["Rating", r["rating"]]])
    for i in r["issues"]: ui.warn(i)
    if not r["issues"]: ui.ok("No common weaknesses detected.")
    for x in r["recommendations"]: ui.info(x)
    config.SESSION["password_check"] = {"rating": r["rating"], "score": r["score"]}      # never the password itself
