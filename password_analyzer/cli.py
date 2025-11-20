import argparse
from .analyzer import analyze_password, load_wordlist, FUZZY_DISTANCE, WORDLIST_PATH

def pretty_print(out):
    print("\n--- Password Analysis Report ---")
    print(f"Password: {out['password']}")
    print(f"Leet-normalized: {out['leet_normalized']}")
    print(f"Length: {out['length']}")
    print(f"Score: {out['score']}/10")
    print(f"Strength: {out['strength']}")
    print(f"Estimated Entropy: {out['entropy_bits']:.2f} bits\n")
    try:
        from .analyzer import human_time
        for label, secs in out["bruteforce_times_seconds"].items():
            print(f"- {label}: {human_time(secs)}")
    except Exception:
        for label, secs in out["bruteforce_times_seconds"].items():
            print(f"- {label}: {secs:.2e} seconds")
    if out["feedback"]:
        print("\nSuggestions:")
        for f in out["feedback"]:
            print("- " + f)

def main():
    parser = argparse.ArgumentParser(prog="password-analyzer", description="Analyze password strength and patterns.")
    parser.add_argument("password", help="Password string to analyze")
    parser.add_argument("--fuzzy", type=int, default=FUZZY_DISTANCE, help="Levenshtein max distance for fuzzy dict matches")
    args = parser.parse_args()

    wordset = load_wordlist(WORDLIST_PATH)
    out = analyze_password(args.password, wordset, fuzzy_maxdist=args.fuzzy)
    pretty_print(out)

if __name__ == "__main__":
    main()
