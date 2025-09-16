"""
safe_osint.py

Safe, beginner-friendly OSINT helper (for lawful use only).
- Generates username & email permutations from a full name.
- Checks public profile existence on common sites (by HTTP status).
- Optionally checks HaveIBeenPwned (api key needed).
"""

import requests
import time
import itertools
import re

# ---------- CONFIG ----------
USER_AGENT = "Mozilla/5.0 (compatible; SafeOSINT/1.0)"
SITES = {
    "GitHub": "https://github.com/{}",
    "X": "https://x.com/{}",              # formerly twitter
    "Instagram": "https://instagram.com/{}",
    "Reddit": "https://reddit.com/user/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://pinterest.com/{}/",
    "StackOverflow": "https://stackoverflow.com/users/{}"  # username here may not resolve easily
}
HIBP_API_KEY = None  # Put your HIBP API key here if you want email checks (optional)
RATE_LIMIT_SECONDS = 1.0  # be kind to servers

# ---------- HELPERS ----------
def slugify(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())

def name_parts(full_name):
    parts = [p for p in re.split(r'\s+', full_name.strip()) if p]
    return parts

def generate_usernames(full_name):
    """Generate common username permutations from a person's name."""
    parts = name_parts(full_name)
    if not parts:
        return []

    first = parts[0].lower()
    last = parts[-1].lower() if len(parts) > 1 else ""
    initials = ''.join(p[0].lower() for p in parts)

    candidates = set()

    # basic forms
    candidates.update([
        first,
        last,
        initials,
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{first}-{last}"
    ])

    # include middle initials if present
    if len(parts) > 2:
        mid = parts[1].lower()
        candidates.add(f"{first}{mid}")
        candidates.add(f"{first}{mid[0]}{last}")
        candidates.add(f"{first[0]}{mid[0]}{last}")

    # add numeric small suffixes (common)
    for base in list(candidates):
        for n in range(1, 4):
            candidates.add(f"{base}{n}")

    # clean
    return sorted(slugify(u) for u in candidates)

def generate_emails(full_name, domains):
    """Generate likely email permutations for given domains.
       domains: list like ["gmail.com", "example.com"]
    """
    parts = name_parts(full_name)
    if not parts: return []
    first = parts[0].lower()
    last = parts[-1].lower() if len(parts) > 1 else ''
    initials = ''.join(p[0].lower() for p in parts)

    patterns = []
    patterns.extend([
        "{first}.{last}",
        "{first}{last}",
        "{f}{last}",
        "{first}{l}",
        "{first}",
        "{last}",
        "{initials}",
        "{first}_{last}"
    ])

    emails = set()
    for d in domains:
        for pat in patterns:
            local = pat.format(first=first, last=last, f=first[0] if first else '',
                               l=last[0] if last else '', initials=initials)
            local = re.sub(r'[^a-z0-9._-]', '', local)
            emails.add(f"{local}@{d}")

    return sorted(emails)

def check_profile_exists(url):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=7, allow_redirects=True)
        # 200 likely exists; 301/302 redirected to login or profile might still mean exists for some sites.
        if r.status_code == 200:
            return True, r.status_code
        # Some sites return 200 for all pages (so this is heuristic)
        if r.status_code in (301, 302):
            return True, r.status_code
        return False, r.status_code
    except requests.RequestException as e:
        return None, str(e)

def hibp_check_email(email):
    """Requires HIBP API key. Returns True if found, False if not, None on error or no key."""
    if not HIBP_API_KEY:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "User-Agent": USER_AGENT,
        "hibp-api-key": HIBP_API_KEY,
        "Accept": "application/json"
    }
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
        return None
    except requests.RequestException:
        return None

# ---------- MAIN ----------
def find_public_accounts(full_name, domains_for_emails=None, max_results=50):
    usernames = generate_usernames(full_name)
    if domains_for_emails is None:
        domains_for_emails = ["gmail.com", "yahoo.com", "outlook.com"]

    emails = generate_emails(full_name, domains_for_emails)

    found = {"usernames": [], "emails": []}

    print(f"Generated {len(usernames)} username candidates and {len(emails)} email candidates.")
    checked = 0

    # check usernames on public sites
    for u in usernames:
        for site_name, pattern in SITES.items():
            url = pattern.format(u)
            exists, info = check_profile_exists(url)
            time.sleep(RATE_LIMIT_SECONDS)
            checked += 1
            if exists:
                found["usernames"].append({"site": site_name, "username": u, "url": url, "status": info})
            if checked >= max_results:
                print("Reached max_results, stopping early.")
                return found

    # check emails via HIBP (optional) - this does NOT reveal account locations, only breach presence
    for e in emails:
        hibp = hibp_check_email(e)
        time.sleep(RATE_LIMIT_SECONDS)
        if hibp is True:
            found["emails"].append({"email": e, "pwned": True})
        elif hibp is False:
            # optionally include non-pwned entries if you want
            pass

    return found

if __name__ == "__main__":
    print("SAFE OSINT HELPER — lawful use only")
    name = input("Enter full name (for permutations): ").strip()
    domains_input = input("Comma-separated domains to try for emails (or press Enter for defaults): ").strip()
    domains = [d.strip() for d in domains_input.split(",")] if domains_input else None

    results = find_public_accounts(name, domains_for_emails=domains)
    print("\n== Results ==")
    print("Public profiles found (username style):")
    for r in results["usernames"]:
        print(f" - {r['site']}: {r['url']} (status: {r['status']})")

    if results["emails"]:
        print("\nEmails found in breach data (HaveIBeenPwned):")
        for r in results["emails"]:
            print(f" - {r['email']} : pwned")
    else:
        print("\nNo emails flagged via HIBP (or HIBP not checked).")
