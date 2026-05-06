import pytest
from pipeline.scorer import (
    DefconFactors,
    _extract_cvss,
    _extract_impact_raw,
    _extract_keyword_raw,
    compute_article_score,
    compute_global_score,
)


@pytest.mark.parametrize("vol,cve,impact,kw,expected_level,expected_term,expected_color", [
    (0.0,  0.0,  0.0,  0.0,  5, "Fade Out",       "#3b82f6"),  # total=0
    (5.0,  5.0,  5.0,  3.0,  5, "Fade Out",       "#3b82f6"),  # total=18
    (5.0,  5.0,  5.0,  5.0,  4, "Double Take",    "#22c55e"),  # total=20
    (10.0, 10.0, 10.0, 9.0,  4, "Double Take",    "#22c55e"),  # total=39
    (10.0, 10.0, 10.0, 10.0, 3, "Round House",    "#eab308"),  # total=40
    (15.0, 15.0, 15.0, 14.0, 3, "Round House",    "#eab308"),  # total=59
    (15.0, 15.0, 15.0, 15.0, 2, "Fast Pace",      "#dc2626"),  # total=60
    (20.0, 20.0, 19.0, 20.0, 2, "Fast Pace",      "#dc2626"),  # total=79
    (20.0, 20.0, 20.0, 20.0, 1, "Cocked Pistol",  "#ffffff"),  # total=80
    (25.0, 25.0, 25.0, 25.0, 1, "Cocked Pistol",  "#ffffff"),  # total=100
])
def test_defcon_level_label_color(vol, cve, impact, kw, expected_level, expected_term, expected_color):
    factors = DefconFactors(
        volume_score=vol,
        cve_score=cve,
        impact_score=impact,
        keyword_score=kw,
    )
    assert factors.level == expected_level, f"score={factors.total:.0f}: expected level {expected_level}, got {factors.level}"
    assert factors.label == expected_term,  f"level {factors.level}: expected '{expected_term}', got '{factors.label}'"
    assert factors.color == expected_color, f"level {factors.level}: expected color '{expected_color}', got '{factors.color}'"


def test_boundary_exactly_80_is_defcon1():
    f = DefconFactors(20.0, 20.0, 20.0, 20.0)
    assert f.total == 80.0
    assert f.level == 1


def test_boundary_exactly_20_is_defcon4():
    f = DefconFactors(5.0, 5.0, 5.0, 5.0)
    assert f.total == 20.0
    assert f.level == 4


def test_zero_articles_returns_defcon5():
    f = DefconFactors(0.0, 0.0, 0.0, 0.0)
    assert f.level == 5
    assert f.label == "Fade Out"


# --- _extract_cvss ---

def test_extract_cvss_explicit():
    assert _extract_cvss("cvss 9.8 critical flaw") == pytest.approx(9.8)

def test_extract_cvss_with_colon():
    assert _extract_cvss("CVSS: 7.5 high severity") == pytest.approx(7.5)

def test_extract_cvss_version_qualifier_ignored():
    # "CVSSv3.1: 9.8" — should return 9.8 (the score), not 3.1 (the version)
    assert _extract_cvss("CVSSv3.1: 9.8 critical flaw") == pytest.approx(9.8)

def test_extract_cvss_vector_string_no_false_positive():
    # Bare CVSS vector without a numeric score should return 0, not a version digit
    assert _extract_cvss("CVSSv3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 0.0

def test_extract_cvss_out_of_range_ignored():
    # Out-of-range CVSS should not be returned; fallback to severity words or 0
    assert _extract_cvss("cvss 11.0 flaw") == 0.0

def test_extract_cvss_severity_fallback_critical():
    assert _extract_cvss("critical vulnerability no explicit score") == pytest.approx(9.0)

def test_extract_cvss_severity_fallback_high():
    assert _extract_cvss("high severity flaw") == pytest.approx(7.0)

def test_extract_cvss_no_signals():
    assert _extract_cvss("routine software update released") == 0.0


# --- _extract_impact_raw ---

def test_extract_impact_raw_actively_exploited():
    assert _extract_impact_raw("actively exploited in the wild") == 6

def test_extract_impact_raw_critical_sector():
    assert _extract_impact_raw("hospital systems targeted by attackers") == 5

def test_extract_impact_raw_million():
    assert _extract_impact_raw("2 million users affected") == 4

def test_extract_impact_raw_countries_above_threshold():
    assert _extract_impact_raw("spread to 10 countries") == 4

def test_extract_impact_raw_countries_below_threshold():
    assert _extract_impact_raw("reported in 3 countries") == 0

def test_extract_impact_raw_data_breach():
    assert _extract_impact_raw("data breach exposed credentials") == 3

def test_extract_impact_raw_large_record_count():
    assert _extract_impact_raw("1500000 records stolen") == 3

def test_extract_impact_raw_no_signals():
    assert _extract_impact_raw("minor software advisory") == 0

def test_extract_impact_raw_stacks():
    # hospital(5) + actively exploited(6) + 2 million(4) = 15
    assert _extract_impact_raw("hospital actively exploited 2 million users") == 15


# --- _extract_keyword_raw ---

def test_extract_keyword_raw_tier1_zero_day():
    # TIER1 "zero-day" = 8 pts; "exploit" is TIER3 = 1 pt
    assert _extract_keyword_raw("zero-day exploit used in attack") == 9

def test_extract_keyword_raw_zero_day_not_double_counted():
    # "zero-day" should only score via TIER1 (8), not also via TIER3
    score_with_zero_day = _extract_keyword_raw("zero-day exploit")
    score_exploit_only  = _extract_keyword_raw("exploit")
    assert score_with_zero_day - score_exploit_only == 8

def test_extract_keyword_raw_tier2_only():
    # "ransomware" is TIER2 (4); "ransomware attack" is TIER1 (8) — text has neither of those
    assert _extract_keyword_raw("ransomware detected on endpoint") == 4

def test_extract_keyword_raw_tier3():
    assert _extract_keyword_raw("vulnerability patch released") == 2

def test_extract_keyword_raw_no_keywords():
    assert _extract_keyword_raw("weather update today") == 0


# --- compute_article_score ---

def test_article_score_empty_is_zero():
    assert compute_article_score("", "") == 0.0

def test_article_score_no_phantom_volume():
    # Under the old scheme an empty article scored ~2 due to the volume dimension.
    # New scheme: no volume, so truly empty = 0.
    assert compute_article_score("no keywords here", "") == 0.0

def test_article_score_critical_reaches_defcon1():
    score = compute_article_score(
        "Nation-state zero-day attack on critical infrastructure",
        "CVSS 9.8 actively exploited power grid government military",
    )
    assert score >= 80.0

def test_article_score_rce_actively_exploited_is_defcon2_or_3():
    score = compute_article_score(
        "RCE vulnerability actively exploited in the wild",
        "CVSS 9.0 remote code execution data breach exposed",
    )
    assert 60.0 <= score < 80.0

def test_article_score_routine_patch_is_defcon4_or_5():
    score = compute_article_score(
        "Microsoft patches medium severity CVE-2024-1234",
        "CVSS 5.0 vulnerability fixed in monthly update patch",
    )
    assert score < 40.0


# --- compute_global_score ---

def test_global_score_empty_articles_returns_zero():
    factors = compute_global_score([], new_count=0, avg_volume=None)
    assert factors.total == 0.0

def test_global_score_volume_cold_start_is_neutral():
    articles = [{"title": "malware detected", "summary": "ransomware"}]
    factors = compute_global_score(articles, new_count=5, avg_volume=None)
    assert factors.volume_score == pytest.approx(12.5)

def test_global_score_volume_at_baseline_is_neutral():
    articles = [{"title": "malware detected", "summary": "ransomware"}]
    factors = compute_global_score(articles, new_count=10, avg_volume=10.0)
    assert factors.volume_score == pytest.approx(12.5)

def test_global_score_volume_double_spike_maxes():
    articles = [{"title": "malware detected", "summary": "ransomware"}]
    factors = compute_global_score(articles, new_count=20, avg_volume=10.0)
    assert factors.volume_score == pytest.approx(25.0)

def test_global_score_volume_half_baseline_is_low():
    articles = [{"title": "malware detected", "summary": "ransomware"}]
    factors = compute_global_score(articles, new_count=5, avg_volume=10.0)
    assert factors.volume_score == pytest.approx(6.25)

def test_global_score_cve_fallback_fires_per_article():
    """Both articles should contribute to cve_score even when only one has explicit CVSS."""
    articles = [
        {"title": "CVSS 9.8 critical remote code execution flaw", "summary": "explicit score"},
        {"title": "critical vulnerability actively exploited", "summary": "no explicit cvss here"},
    ]
    factors = compute_global_score(articles, new_count=2, avg_volume=10.0)
    # avg_cvss = (9.8 + 9.0) / 2 = 9.4  →  cve_score = (9.4/10) * 25 = 23.5
    assert factors.cve_score == pytest.approx(23.5, abs=0.5)

def test_global_score_articles_without_cve_pull_average_down():
    """Articles with no CVE signals should contribute 0 and lower the average."""
    articles = [
        {"title": "CVSS 10.0 critical flaw", "summary": ""},
        {"title": "routine software release", "summary": "no threats"},
    ]
    factors = compute_global_score(articles, new_count=2, avg_volume=10.0)
    # article 1: explicit CVSS 10.0 → 10.0; article 2: no signals → 0.0
    # avg_cvss = (10.0 + 0.0) / 2 = 5.0 → cve_score = 5.0/10 * 25 = 12.5
    assert factors.cve_score == pytest.approx(12.5, abs=0.5)
