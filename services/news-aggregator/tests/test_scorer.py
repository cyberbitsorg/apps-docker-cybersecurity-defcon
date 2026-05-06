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
