from password_analyzer.analyzer import analyze_password, load_wordlist
def test_basic():
    ws = load_wordlist("wordlist.txt")
    out = analyze_password("Abc123!@#", ws, fuzzy_maxdist=0)
    assert "score" in out
