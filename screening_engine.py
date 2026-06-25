"""Process-wide cache for the downloaded sanctions lists, shared by the
public demo endpoint and the authenticated dashboard API so both reuse the
same in-memory data instead of downloading it twice."""

import os

from sanctions_screener import load_lists

_CACHE = {"entries": None, "used_demo": None}


def get_entries(force_refresh: bool = False):
    if _CACHE["entries"] is None or force_refresh:
        eu_token = os.environ.get("EU_SANCTIONS_TOKEN")
        entries, used_demo = load_lists(use_demo=False, force_refresh=force_refresh, eu_token=eu_token)
        _CACHE["entries"] = entries
        _CACHE["used_demo"] = used_demo
    return _CACHE["entries"], _CACHE["used_demo"]
