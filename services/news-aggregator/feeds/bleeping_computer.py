from feeds.base import RssFeedParser


class BleepingComputerFeed(RssFeedParser):
    source_id = "bleeping_computer"
    feed_url = "https://www.bleepingcomputer.com/feed/"
