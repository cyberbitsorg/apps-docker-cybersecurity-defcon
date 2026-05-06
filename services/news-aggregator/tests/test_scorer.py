import pytest
from pipeline.scorer import DefconFactors


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
