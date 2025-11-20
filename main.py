# Password-Analyzer
import string
import math
import os
import re

# ---------- CONFIG ----------
MIN_DICT_WORD_LEN = 4        # only consider dictionary words of this length or more
FUZZY_DISTANCE = 1           # max edit distance for fuzzy match (set 0 to disable)
WORDLIST_PATH = "wordlist.txt"  # place a wordlist here (one word per line) to use real dictionary
# ---------- END CONFIG ----------

# small built-in common passwords (you can replace with a bigger file later)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123",
    "111111", "123456789", "12345", "1234", "password1",
    "admin", "letmein", "welcome", "monkey", "dragon"
}

# small fallback dictionary (keeps script usable if you don't provide a file)
FALLBACK_DICT = {
    "password", "admin", "user", "login", "welcome", "hello",
    "secret", "bitcoin", "football", "qwerty", "security", "hacker", "letmein"
}

# keyboard patterns to detect (add more if you like)
KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qaz", "wasd", "1q2w", "password", "iloveyou", "letmein"
]

# basic leet substitution map (from leet char -> probable plain letter)
LEET_MAP = {
    # ---------------- MULTI-CHAR PATTERNS (checked first) ----------------
    "|3": "b",
    "13": "b",
    "|}": "d",
    "|>": "k",
    "|<": "k",
    "|(": "k",
    "|]": "d",
    "|)": "d",
    "|0": "d",
    "|=": "f",
    "|_": "l",
    "|\\|": "n",
    "|V": "n",
    "|/": "y",
    "|\\": "y",
    "|<|": "h",         # hacky but used
    "ph": "f",
    "|-|": "h",
    "]-[": "h",
    ")-(": "h",
    "<-<": "k",
    "vv": "w",
    "\\/\\/": "w",
    "\\/\\/" : "w",
    "\\/": "v",
    "><": "x",
    ")(": "c",
    "}{": "h",
    "]['": "n",

    # ---------------- SINGLE-CHAR MAPPINGS ----------------
    "0": "o",
    "1": "i",    # choose i (more accurate for dictionary detection)
    "!": "i",
    "|": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "@": "a",
    "5": "s",
    "$": "s",
    "6": "g",
    "7": "t",
    "+": "t",
    "8": "b",
    "9": "g",
    "(": "c",
    "<": "c",
    "{": "c",
    "[": "c",
    "]": "c",
    "}": "c",
    "?": "q",

    # ---------------- OTHER SYMBOLIC SUBS ----------------
    "#": "h",
    "%": "x",
    "&": "and",
    "*": "",       # often filler
    ".": "",
    "-": "",
    "_": "",
}

# ----------------- helpers -----------------

def load_wordlist(path: str):
    """Load words from `path` into a set (lowercased). Falls back to built-in set if file missing."""
    if os.path.isfile(path):
        s = set()
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.strip().lower()
                if len(word) >= MIN_DICT_WORD_LEN:
                    s.add(word)
        return s
    else:
        return set(w for w in FALLBACK_DICT if len(w) >= MIN_DICT_WORD_LEN)


def normalize_leet(s: str) -> str:
    """Return a simplified leet-normalized version of s."""
    normalized = []
    for ch in s.lower():
        if ch in LEET_MAP:
            normalized.append(LEET_MAP[ch])
        else:
            normalized.append(ch)
    return "".join(normalized)


def levenshtein_maxdist(a: str, b: str, maxdist: int):
    """
    Compute Levenshtein distance with early exit if distance > maxdist.
    Returns distance if <= maxdist, else returns any value > maxdist.
    """
    if maxdist <= 0:
        return abs(len(a) - len(b)) if a != b else 0

    if len(a) > len(b):
        a, b = b, a
    la, lb = len(a), len(b)
    if lb - la > maxdist:
        return maxdist + 1

    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        min_in_row = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if cur[j] < min_in_row:
                min_in_row = cur[j]
        if min_in_row > maxdist:
            return maxdist + 1
        prev = cur
    return prev[lb]


def contains_dictionary_words(password: str, dict_set: set, fuzzy_maxdist: int = 0):
    """
    Check for dictionary words inside password.
    Returns list of matches: (word, start_index, end_index, method) where method in {"exact","leet","fuzzy"}
    """
    matches = []
    pwd_lower = password.lower()
    norm_leet = normalize_leet(password)

    # exact and leet-normalized substring matches
    for word in dict_set:
        if len(word) < MIN_DICT_WORD_LEN:
            continue
        idx = pwd_lower.find(word)
        if idx != -1:
            matches.append((word, idx, idx + len(word), "exact"))
            continue
        idx2 = norm_leet.find(word)
        if idx2 != -1:
            matches.append((word, idx2, idx2 + len(word), "leet"))
            continue

    # fuzzy check (optional, costs more)
    if fuzzy_maxdist > 0:
        n = len(pwd_lower)
        for start in range(n):
            for end in range(start + MIN_DICT_WORD_LEN, min(n, start + 20) + 1):
                sub = pwd_lower[start:end]
                for word in dict_set:
                    if abs(len(word) - len(sub)) > fuzzy_maxdist:
                        continue
                    dist = levenshtein_maxdist(sub, word, fuzzy_maxdist)
                    if dist <= fuzzy_maxdist:
                        matches.append((word, start, end, f"fuzzy(d={dist})"))
                        break
    return matches


# ----------------- pattern detection -----------------

def has_repeated_char_seq(s: str, min_repeat=4):
    """Detect same character repeated min_repeat times e.g. 'aaaa' or '1111'"""
    m = re.search(r"(.)\1{" + str(min_repeat - 1) + r",}", s)
    return bool(m), (m.group(0) if m else None)


def has_repeated_unit_seq(s: str, unit_max=4):
    """
    Detect repeated unit sequences like '121212', 'ababab', where a unit of length 1..unit_max repeats.
    """
    n = len(s)
    for unit_len in range(1, unit_max + 1):
        for start in range(0, n - unit_len * 2 + 1):
            unit = s[start:start + unit_len]
            i = start
            count = 0
            while s[i:i + unit_len] == unit:
                count += 1
                i += unit_len
                if i + unit_len > n:
                    break
            if count >= 2 and count * unit_len >= 4:
                return True, unit * count
    return False, None


def has_sequential_chars(s: str, seq_min=4):
    """
    Detect ascending or descending sequences like 'abcd', '12345' of length >= seq_min.
    """
    s_lower = s.lower()
    n = len(s_lower)
    for i in range(n - seq_min + 1):
        asc = True
        desc = True
        for k in range(1, seq_min):
            if i + k >= n:
                asc = desc = False
                break
            if ord(s_lower[i + k]) != ord(s_lower[i + k - 1]) + 1:
                asc = False
            if ord(s_lower[i + k]) != ord(s_lower[i + k - 1]) - 1:
                desc = False
        if asc or desc:
            j = i + seq_min
            while j < n and (ord(s_lower[j]) == ord(s_lower[j - 1]) + (1 if asc else -1)):
                j += 1
            return True, s_lower[i:j]
    return False, None


def has_keyboard_pattern(s: str):
    """Check for common keyboard patterns and their reversals."""
    s_lower = s.lower()
    for pat in KEYBOARD_PATTERNS:
        if pat in s_lower or pat[::-1] in s_lower:
            return True, pat
    return False, None


# ----------------- entropy & brute-force helpers -----------------

def human_time(seconds: float) -> str:
    """Convert seconds to human readable form (approx)."""
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    intervals = (
        ('years', 60*60*24*365),
        ('days', 60*60*24),
        ('hours', 60*60),
        ('minutes', 60),
        ('seconds', 1),
    )
    parts = []
    remaining = int(seconds)
    for name, count in intervals:
        if remaining >= count:
            val = remaining // count
            remaining = remaining % count
            parts.append(f"{val} {name}")
    return ', '.join(parts) if parts else "0 seconds"


def estimate_entropy(password: str) -> float:
    """
    Estimate entropy (bits) using charset size method:
    H = L * log2(N)
    """
    L = len(password)
    if L == 0:
        return 0.0
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if charset_size == 0:
        charset_size = 50
    entropy = L * math.log2(charset_size)
    return entropy


def brute_force_time_seconds(entropy_bits: float, attempts_per_second: float) -> float:
    """
    Estimate time to try half the keyspace on average:
    avg_attempts = 2^(entropy-1)
    time (s) = avg_attempts / attempts_per_second
    """
    if entropy_bits <= 0:
        return 0.0
    avg_attempts = 2 ** (entropy_bits - 1)
    return avg_attempts / attempts_per_second


# ----------------- main analyzer (merged) -----------------

def analyze_password(password: str, dict_set: set, fuzzy_maxdist: int = 0):
    """
    Full analysis combining Day-1/2 (score, entropy, brute-force, common checks)
    and Day-3 (dictionary, leet, sequences, keyboard patterns).
    Returns a detailed result dict.
    """
    score = 0
    feedback = []

    # Basic rule checks (score out of 10)
    if len(password) >= 8:
        score += 2
    else:
        feedback.append("Length should be at least 8 characters.")
    if any(c.isupper() for c in password):
        score += 2
    else:
        feedback.append("Add at least one uppercase letter.")
    if any(c.islower() for c in password):
        score += 2
    else:
        feedback.append("Add at least one lowercase letter.")
    if any(c.isdigit() for c in password):
        score += 2
    else:
        feedback.append("Add at least one digit.")
    if any(c in string.punctuation for c in password):
        score += 2
    else:
        feedback.append("Add at least one special symbol (e.g. !@#$%).")

    # Entropy & brute-force
    entropy = estimate_entropy(password)
    speeds = {
        "1,000/sec (slow/offline)": 1e3,
        "1,000,000/sec (common GPU)": 1e6,
        "1,000,000,000/sec (massive GPU/ASIC farm)": 1e9
    }
    bruteforce_times = {label: brute_force_time_seconds(entropy, rate) for label, rate in speeds.items()}

    # Common password checks
    lower_pwd = password.lower()
    is_common = lower_pwd in COMMON_PASSWORDS
    contains_common = any(common in lower_pwd for common in COMMON_PASSWORDS)
    if is_common:
        feedback.append("Password is a common password — avoid exact common passwords.")
        score = max(0, score - 4)
    elif contains_common:
        feedback.append("Password contains a common password substring (e.g., '1234' or 'password'). Consider removing it.")
        score = max(0, score - 2)

    # Dictionary / leet / fuzzy checks (Day 3)
    dict_matches = contains_dictionary_words(password, dict_set, fuzzy_maxdist)
    contains_dict = len(dict_matches) > 0
    if contains_dict:
        # add descriptive feedback for each match
        for word, s, e, method in dict_matches:
            feedback.append(f"Contains dictionary word '{word}' at [{s}:{e}] via {method} check.")
        # penalize score a bit
        score = max(0, score - 2)

    # pattern detections
    rep_char_found, rep_char_seq = has_repeated_char_seq(password)
    rep_unit_found, rep_unit_seq = has_repeated_unit_seq(password)
    seq_found, seq_str = has_sequential_chars(password)
    kb_found, kb_pat = has_keyboard_pattern(password)

    if rep_char_found:
        feedback.append(f"Repeated character sequence detected: {rep_char_seq}")
        score = max(0, score - 2)
    if rep_unit_found:
        feedback.append(f"Repeated unit sequence detected: {rep_unit_seq}")
        score = max(0, score - 1)
    if seq_found:
        feedback.append(f"Sequential characters detected: {seq_str}")
        score = max(0, score - 1)
    if kb_found:
        feedback.append(f"Keyboard pattern detected: {kb_pat}")
        score = max(0, score - 1)

    # Strength label
    if score >= 9:
        strength = "Strong"
    elif score >= 6:
        strength = "Moderate"
    else:
        strength = "Weak"

    result = {
        "password": password,
        "length": len(password),
        "score": score,
        "strength": strength,
        "entropy_bits": entropy,
        "bruteforce_times_seconds": bruteforce_times,
        "is_common_exact": is_common,
        "contains_common_substring": contains_common,
        "dictionary_matches": dict_matches,
        "repeated_char_sequence": rep_char_seq if rep_char_found else None,
        "repeated_unit_sequence": rep_unit_seq if rep_unit_found else None,
        "sequential_chars": seq_str if seq_found else None,
        "keyboard_pattern": kb_pat if kb_found else None,
        "leet_normalized": normalize_leet(password),
        "feedback": feedback
    }
    return result


# ---------------- runnable demo ----------------

if __name__ == "__main__":
    # load dictionary (provide wordlist.txt in same folder if you want a big list)
    wordset = load_wordlist(WORDLIST_PATH)
    print(f"Loaded dictionary words: {len(wordset)} (using {WORDLIST_PATH if os.path.isfile(WORDLIST_PATH) else 'fallback set'})\n")

    pwd = input("Enter the password to analyze: ").strip()
    out = analyze_password(pwd, wordset, fuzzy_maxdist=FUZZY_DISTANCE)

    print("\n--- Password Analysis Report ---")
    print(f"Password: {out['password']}")
    print(f"Leet-normalized: {out['leet_normalized']}")
    print(f"Length: {out['length']}")
    print(f"Score: {out['score']}/10")
    print(f"Strength: {out['strength']}")
    print(f"Estimated Entropy: {out['entropy_bits']:.2f} bits")

    print("\nEstimated average brute-force time (approx):")
    for label, secs in out["bruteforce_times_seconds"].items():
        print(f"- {label}: {human_time(secs)}")

    if out["is_common_exact"]:
        print("\nWARNING: Exact match with a known common password list.")
    if out["contains_common_substring"]:
        print("\nWARNING: Contains common password substring.")
    if out["dictionary_matches"]:
        print("\nDictionary / common-word matches:")
        for word, s, e, method in out["dictionary_matches"]:
            print(f"- '{word}' at [{s}:{e}] via {method}")

    if out["repeated_char_sequence"]:
        print(f"\nRepeated-char sequence: {out['repeated_char_sequence']}")
    if out["repeated_unit_sequence"]:
        print(f"Repeated-unit sequence: {out['repeated_unit_sequence']}")
    if out["sequential_chars"]:
        print(f"Sequential characters: {out['sequential_chars']}")
    if out["keyboard_pattern"]:
        print(f"Keyboard pattern detected: {out['keyboard_pattern']}")

    if out["feedback"]:
        print("\nSuggestions:")
        for f in out["feedback"]:
            print("- " + f)
