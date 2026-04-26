import pytest
import respx
import httpx
from datetime import timezone
from feeds.base import _parse_date, _strip_html, RssFeedParser

SAMPLE_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>https://example.com/article1</id>
    <title>Test Security Article</title>
    <link href="https://example.com/article1"/>
    <published>2026-04-24T14:15:00Z</published>
    <summary>A test summary about vulnerabilities.</summary>
  </entry>
  <entry>
    <id>https://example.com/article2</id>
    <title>Another Article</title>
    <link href="https://example.com/article2"/>
    <summary>No date entry — should be skipped.</summary>
  </entry>
</feed>"""


class ConcreteRssFeed(RssFeedParser):
    source_id = "test_feed"
    feed_url = "https://example.com/feed.atom"


def test_parse_date_valid_utc():
    dt = _parse_date("2026-04-24T14:15:00Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2026 and dt.month == 4 and dt.day == 24


def test_parse_date_rss_format():
    dt = _parse_date("Thu, 24 Apr 2026 14:15:00 +0000")
    assert dt is not None
    assert dt.tzinfo is not None


def test_parse_date_naive_becomes_utc():
    dt = _parse_date("2026-04-24T14:15:00")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_parse_date_empty_returns_none():
    assert _parse_date("") is None
    assert _parse_date(None) is None


def test_strip_html_removes_tags():
    assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"


def test_strip_html_collapses_whitespace():
    assert _strip_html("<p>  too   many   spaces  </p>") == "too many spaces"


def test_strip_html_plain_text_unchanged():
    assert _strip_html("plain text") == "plain text"


@pytest.mark.asyncio
async def test_rss_feed_parser_returns_articles():
    feed = ConcreteRssFeed()
    with respx.mock:
        respx.get("https://example.com/feed.atom").mock(
            return_value=httpx.Response(200, text=SAMPLE_ATOM)
        )
        articles = await feed.fetch()

    assert len(articles) == 1  # second entry has no date → skipped
    a = articles[0]
    assert a.source == "test_feed"
    assert a.title == "Test Security Article"
    assert a.url == "https://example.com/article1"
    assert a.published_at.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_rss_feed_parser_returns_empty_on_http_error():
    feed = ConcreteRssFeed()
    with respx.mock:
        respx.get("https://example.com/feed.atom").mock(
            return_value=httpx.Response(403)
        )
        articles = await feed.fetch()

    assert articles == []
