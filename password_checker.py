"""Simple password strength and breach-exposure checker."""

import hashlib
import re
import sys
import urllib.parse
import urllib.request

COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "qwerty", "password",
    "111111", "123123", "admin", "letmein", "welcome", "abc123",
}
SEQUENTIAL_PATTERNS = ("012345", "123456", "abcdef", "qwerty")


def password_strength(password: str) -> dict:
    """Return a strength label, score, and improvement suggestions."""
    tips = []
    score = 0

    length = len(password)
    if length >= 16:
        score += 4
    elif length >= 12:
        score += 3
    elif length >= 8:
        score += 2
    else:
        tips.append("Use at least 12 characters.")

    classes = (
        (re.search(r"[a-z]", password), "Add lowercase letters."),
        (re.search(r"[A-Z]", password), "Add uppercase letters."),
        (re.search(r"\d", password), "Add numbers."),
        (re.search(r"[^A-Za-z0-9]", password), "Add symbols."),
    )
    for matched, tip in classes:
        if matched:
            score += 1
        else:
            tips.append(tip)

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        score -= 4
        tips.append("Replace this commonly used password.")
    if any(pattern in lowered for pattern in SEQUENTIAL_PATTERNS):
        score -= 2
        tips.append("Avoid predictable letters or numbers.")
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        tips.append("Avoid repeating the same character.")

    score = max(0, min(10, score))
    if score <= 3:
        label = "Weak"
    elif score <= 6:
        label = "Moderate"
    elif score <= 8:
        label = "Strong"
    else:
        label = "Very strong"

    return {"score": score, "label": label, "tips": tips}


def check_breach_count(password: str, timeout: float = 8.0) -> int:
    """Query HIBP using k-anonymity and return the matching breach count."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = "https://api.pwnedpasswords.com/range/" + urllib.parse.quote(prefix)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "password-security-checker"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        for line in response.read().decode("ascii").splitlines():
            returned_suffix, count = line.split(":", 1)
            if returned_suffix == suffix:
                return int(count)
    return 0


def main() -> int:
    if len(sys.argv) > 1:
        print("Usage: python password_checker.py", file=sys.stderr)
        return 2

    try:
        import getpass
        password = getpass.getpass("Enter a password to check: ")
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130

    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        return 1

    result = password_strength(password)
    print(f"Strength: {result['label']} ({result['score']}/10)")
    if result["tips"]:
        print("Suggestions:")
        for tip in result["tips"]:
            print(f"- {tip}")

    try:
        breaches = check_breach_count(password)
    except Exception as exc:
        print(f"Breach check unavailable: {exc}")
        return 0

    if breaches:
        print(f"Warning: found in known breaches {breaches:,} times.")
    else:
        print("No matching password found in the breach database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
