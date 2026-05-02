from feeds.base import RssFeedParser


class HackerNewsFeed(RssFeedParser):
    source_id = "hacker_news"
    feed_url = "https://thehackernews.com/feeds/posts/default"
