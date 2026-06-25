#!/usr/bin/env python3
"""
Sanctions Screening Assistant
=============================

A screening AID for checking a name/entity against PUBLIC, OFFICIAL sanctions
lists (OFAC SDN, UN Security Council Consolidated List, and optionally the EU
Consolidated List). It performs fuzzy name matching and returns a ranked list
of potential matches for HUMAN REVIEW.

WHAT THIS TOOL IS:
- A first-pass filter to help a person prioritize manual review.
- Built entirely on official, freely published government/IGO data.

WHAT THIS TOOL IS NOT:
- It is NOT a guarantee of legal compliance.
- It does NOT replace a compliance officer, lawyer, or licensed KYC/AML
  provider.
- A "no match" result means "no match found against the lists loaded at the
  time of the last refresh" -- not "this person/entity is definitely not
  sanctioned anywhere in the world."
- Sanctions screening in real institutions also checks date of birth,
  nationality, ID numbers, and ownership structures (e.g. the "50% rule" for
  entities owned by a sanctioned person). Name matching alone is one layer,
  not the whole control.

Data sources (official, public, no scraping of restricted content):
- OFAC Specially Designated Nationals (SDN) List
  https://www.treasury.gov/ofac/downloads/sdn.xml
- UN Security Council Consolidated List
  https://scsanctions.un.org/resources/xml/en/consolidated.xml
- EU Consolidated Financial Sanctions List (OPTIONAL - requires a free token
  issued by the European Commission's FSF system; see README.md)

Usage:
    python3 sanctions_screener.py --refresh
    python3 sanctions_screener.py --name "John Smith"
    python3 sanctions_screener.py --file customers.csv --name-column full_name
    python3 sanctions_screener.py --demo --name "Test Sanctioned Entity Alpha"
"""

import argparse
import csv
import json
import os
import re
import sys
import unicodedata
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    from rapidfuzz import fuzz as _rapidfuzz_fuzz
    _HAVE_RAPIDFUZZ = True
except ImportError:
    import difflib
    _HAVE_RAPIDFUZZ = False

CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
UN_CONSOLIDATED_XML_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
USER_AGENT = "SanctionsScreeningAssistant/1.0 (research/compliance-aid tool)"
REQUEST_TIMEOUT = 30


# --------------------------------------------------------------------------
# Name normalization & matching
# --------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    """Lowercase, strip accents/diacritics, collapse whitespace and punctuation."""
    if not name:
        return ""
    name = unicodedata.normalize("NFKD", name)
    name = "".join(ch for ch in name if not unicodedata.combining(ch))
    name = name.lower()
    name = re.sub(r"[^a-z0-9\s]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name


def similarity_score(a: str, b: str) -> float:
    """Return a 0-100 similarity score between two normalized strings."""
    if _HAVE_RAPIDFUZZ:
        # token_sort_ratio handles word-order differences (e.g. "Smith John"
        # vs "John Smith") better than a plain ratio.
        return _rapidfuzz_fuzz.token_sort_ratio(a, b)
    else:
        # Fallback: stdlib difflib, plus a manual token-sort step so word
        # order differences don't tank the score.
        a_sorted = " ".join(sorted(a.split()))
        b_sorted = " ".join(sorted(b.split()))
        return difflib.SequenceMatcher(None, a_sorted, b_sorted).ratio() * 100


# --------------------------------------------------------------------------
# Data fetching
# --------------------------------------------------------------------------

def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return resp.read()


def _cache_path(name: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def fetch_ofac_sdn(force_refresh: bool = False) -> list:
    """
    Download and parse the OFAC SDN list (XML).
    Returns a list of dicts: {name, type, programs, source, list, uid}
    """
    cache_file = _cache_path("ofac_sdn.xml")
    if force_refresh or not os.path.exists(cache_file):
        raw = _http_get(OFAC_SDN_XML_URL)
        with open(cache_file, "wb") as f:
            f.write(raw)
    with open(cache_file, "rb") as f:
        raw = f.read()

    root = ET.fromstring(raw)
    ns = {"ofac": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}

    def tag(elem, name):
        return elem.find(f"ofac:{name}", ns) if ns else elem.find(name)

    entries = []
    sdn_entries = root.findall("ofac:sdnEntry", ns) if ns else root.findall("sdnEntry")
    for entry in sdn_entries:
        uid_el = tag(entry, "uid")
        first_el = tag(entry, "firstName")
        last_el = tag(entry, "lastName")
        type_el = tag(entry, "sdnType")

        first = first_el.text if first_el is not None and first_el.text else ""
        last = last_el.text if last_el is not None and last_el.text else ""
        full_name = " ".join(p for p in [first, last] if p).strip()
        sdn_type = type_el.text if type_el is not None and type_el.text else "Unknown"

        programs = []
        prog_list_el = tag(entry, "programList")
        if prog_list_el is not None:
            prog_tag = "program"
            progs = prog_list_el.findall(f"ofac:{prog_tag}", ns) if ns else prog_list_el.findall(prog_tag)
            programs = [p.text for p in progs if p.text]

        if full_name:
            entries.append({
                "name": full_name,
                "type": sdn_type,
                "programs": programs,
                "source": "OFAC SDN",
                "uid": uid_el.text if uid_el is not None else None,
            })

        # Also index AKAs (aliases) as separate, linked matchable entries
        aka_list_el = tag(entry, "akaList")
        if aka_list_el is not None:
            aka_tag = "aka"
            akas = aka_list_el.findall(f"ofac:{aka_tag}", ns) if ns else aka_list_el.findall(aka_tag)
            for aka in akas:
                aka_first_el = tag(aka, "firstName")
                aka_last_el = tag(aka, "lastName")
                aka_first = aka_first_el.text if aka_first_el is not None and aka_first_el.text else ""
                aka_last = aka_last_el.text if aka_last_el is not None and aka_last_el.text else ""
                aka_name = " ".join(p for p in [aka_first, aka_last] if p).strip()
                if aka_name:
                    entries.append({
                        "name": aka_name,
                        "type": sdn_type,
                        "programs": programs,
                        "source": "OFAC SDN (alias)",
                        "uid": uid_el.text if uid_el is not None else None,
                        "primary_name": full_name,
                    })
    return entries


def fetch_un_consolidated(force_refresh: bool = False) -> list:
    """
    Download and parse the UN Security Council Consolidated List (XML).
    Returns a list of dicts: {name, type, source, ref_num}
    """
    cache_file = _cache_path("un_consolidated.xml")
    if force_refresh or not os.path.exists(cache_file):
        raw = _http_get(UN_CONSOLIDATED_XML_URL)
        with open(cache_file, "wb") as f:
            f.write(raw)
    with open(cache_file, "rb") as f:
        raw = f.read()

    root = ET.fromstring(raw)
    entries = []

    for individual in root.findall(".//INDIVIDUAL"):
        names = [individual.findtext(f"FIRST_NAME") or "",
                 individual.findtext(f"SECOND_NAME") or "",
                 individual.findtext(f"THIRD_NAME") or "",
                 individual.findtext(f"FOURTH_NAME") or ""]
        full_name = " ".join(n for n in names if n).strip()
        ref_num = individual.findtext("REFERENCE_NUMBER") or ""
        if full_name:
            entries.append({
                "name": full_name,
                "type": "Individual",
                "source": "UN Consolidated List",
                "ref_num": ref_num,
            })
        for alias in individual.findall(".//INDIVIDUAL_ALIAS"):
            alias_name = alias.findtext("ALIAS_NAME") or ""
            if alias_name:
                entries.append({
                    "name": alias_name,
                    "type": "Individual",
                    "source": "UN Consolidated List (alias)",
                    "ref_num": ref_num,
                    "primary_name": full_name,
                })

    for entity in root.findall(".//ENTITY"):
        full_name = entity.findtext("FIRST_NAME") or ""
        ref_num = entity.findtext("REFERENCE_NUMBER") or ""
        if full_name:
            entries.append({
                "name": full_name,
                "type": "Entity",
                "source": "UN Consolidated List",
                "ref_num": ref_num,
            })
        for alias in entity.findall(".//ENTITY_ALIAS"):
            alias_name = alias.findtext("ALIAS_NAME") or ""
            if alias_name:
                entries.append({
                    "name": alias_name,
                    "type": "Entity",
                    "source": "UN Consolidated List (alias)",
                    "ref_num": ref_num,
                    "primary_name": full_name,
                })

    return entries


def fetch_eu_consolidated(token: str, force_refresh: bool = False) -> list:
    """
    OPTIONAL: Download the EU Consolidated Financial Sanctions List (XML).
    Requires a free access token from the European Commission's FSF portal.
    See: https://webgate.ec.europa.eu/fsd/fsf/public/home
    """
    if not token:
        return []
    url = f"https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token={token}"
    cache_file = _cache_path("eu_consolidated.xml")
    if force_refresh or not os.path.exists(cache_file):
        raw = _http_get(url)
        with open(cache_file, "wb") as f:
            f.write(raw)
    with open(cache_file, "rb") as f:
        raw = f.read()

    root = ET.fromstring(raw)
    ns = {"eu": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    entries = []

    def findall(elem, path):
        return elem.findall(f"eu:{path}", ns) if ns else elem.findall(path)

    for entity in findall(root, "sanctionEntity"):
        name_aliases = findall(entity, "nameAlias")
        for alias in name_aliases:
            whole_name = alias.get("wholeName")
            if whole_name:
                entries.append({
                    "name": whole_name,
                    "type": "Individual/Entity",
                    "source": "EU Consolidated List",
                })
    return entries


# --------------------------------------------------------------------------
# Demo data (clearly fictional - for testing the pipeline with no network)
# --------------------------------------------------------------------------

DEMO_ENTRIES = [
    {"name": "Test Sanctioned Entity Alpha", "type": "Entity", "source": "DEMO LIST (fictional)"},
    {"name": "Test Sanctioned Individual Beta", "type": "Individual", "source": "DEMO LIST (fictional)"},
    {"name": "Fictional Shell Trading Company", "type": "Entity", "source": "DEMO LIST (fictional)"},
]


# --------------------------------------------------------------------------
# Screening engine
# --------------------------------------------------------------------------

def load_lists(use_demo: bool, force_refresh: bool, eu_token: str = None):
    """Returns (entries, used_demo_fallback: bool)."""
    if use_demo:
        return DEMO_ENTRIES, True

    all_entries = []
    errors = []

    try:
        all_entries.extend(fetch_ofac_sdn(force_refresh))
    except (urllib.error.URLError, ET.ParseError, OSError) as e:
        errors.append(f"OFAC SDN list unavailable: {e}")

    try:
        all_entries.extend(fetch_un_consolidated(force_refresh))
    except (urllib.error.URLError, ET.ParseError, OSError) as e:
        errors.append(f"UN Consolidated list unavailable: {e}")

    if eu_token:
        try:
            all_entries.extend(fetch_eu_consolidated(eu_token, force_refresh))
        except (urllib.error.URLError, ET.ParseError, OSError) as e:
            errors.append(f"EU Consolidated list unavailable: {e}")

    if errors:
        for e in errors:
            print(f"[WARN] {e}", file=sys.stderr)
        if not all_entries:
            print("[WARN] No list data could be downloaded (no network access, or the "
                  "source is unreachable from this machine). Falling back to small "
                  "fictional DEMO data so you can still test the tool. The results "
                  "below are NOT a real sanctions screening.",
                  file=sys.stderr)
            return DEMO_ENTRIES, True

    return all_entries, False


def screen_name(query_name: str, entries: list, threshold: int = 80) -> list:
    """
    Compare query_name against every loaded entry and return matches
    at or above `threshold` (0-100), sorted by descending score.
    """
    norm_query = normalize_name(query_name)
    matches = []
    for entry in entries:
        norm_entry_name = normalize_name(entry["name"])
        if not norm_entry_name:
            continue
        score = similarity_score(norm_query, norm_entry_name)
        if score >= threshold:
            match = dict(entry)
            match["match_score"] = round(score, 1)
            matches.append(match)
    matches.sort(key=lambda m: m["match_score"], reverse=True)
    return matches


def risk_label(score: float) -> str:
    if score >= 95:
        return "HIGH - near-exact name match, review immediately"
    if score >= 88:
        return "MEDIUM-HIGH - strong similarity, manual review required"
    if score >= 80:
        return "MEDIUM - possible match, manual review recommended"
    return "LOW"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

DISCLAIMER = """\
------------------------------------------------------------------------
DISCLAIMER: This is a screening AID, not a compliance guarantee.
- A "no match" does not mean a person/entity is risk-free.
- All matches require human review before any business decision.
- This tool does not replace legal counsel or a licensed KYC/AML provider.
- Name-only matching misses date-of-birth, ownership-structure, and
  ID-document checks that full compliance programs also require.
------------------------------------------------------------------------
"""


def screen_single(args):
    print(DISCLAIMER)
    entries, used_demo = load_lists(args.demo, args.refresh, args.eu_token)
    print(f"Loaded {len(entries)} reference entries "
          f"({'DEMO data (fictional)' if used_demo else 'official public sanctions lists'}).\n")

    matches = screen_name(args.name, entries, args.threshold)
    if not matches:
        print(f'No matches found for "{args.name}" at or above threshold {args.threshold}.')
        print("Remember: this means no match against the lists currently loaded, not a clean bill of health.")
        return

    print(f'{len(matches)} potential match(es) for "{args.name}":\n')
    for m in matches[:25]:
        print(f"  [{m['match_score']:5.1f}] {m['name']}  ({m['source']})")
        print(f"          Risk: {risk_label(m['match_score'])}")
        if m.get("primary_name"):
            print(f"          Listed under primary name: {m['primary_name']}")
        if m.get("programs"):
            print(f"          Programs: {', '.join(m['programs'])}")
        print()


def screen_batch(args):
    print(DISCLAIMER)
    entries, used_demo = load_lists(args.demo, args.refresh, args.eu_token)
    print(f"Loaded {len(entries)} reference entries "
          f"({'DEMO data (fictional)' if used_demo else 'official public sanctions lists'}).\n")

    out_rows = []
    with open(args.file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if args.name_column not in reader.fieldnames:
            print(f'ERROR: column "{args.name_column}" not found. '
                  f"Available columns: {reader.fieldnames}", file=sys.stderr)
            sys.exit(1)
        for row in reader:
            name = row.get(args.name_column, "").strip()
            matches = screen_name(name, entries, args.threshold) if name else []
            top = matches[0] if matches else None
            out_row = dict(row)
            out_row["screening_match_count"] = len(matches)
            out_row["top_match_name"] = top["name"] if top else ""
            out_row["top_match_score"] = top["match_score"] if top else ""
            out_row["top_match_source"] = top["source"] if top else ""
            out_row["risk_flag"] = risk_label(top["match_score"]) if top else "LOW - no match"
            out_rows.append(out_row)

    fieldnames = list(out_rows[0].keys()) if out_rows else []
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    flagged = sum(1 for r in out_rows if r["screening_match_count"] > 0)
    print(f"Screened {len(out_rows)} record(s). {flagged} flagged for manual review.")
    print(f"Results written to: {args.output}")


def main():
    parser = argparse.ArgumentParser(
        description="Sanctions screening assistant (OFAC SDN + UN Consolidated List + optional EU list).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DISCLAIMER,
    )
    parser.add_argument("--name", help="Single name/entity to screen.")
    parser.add_argument("--file", help="CSV file of records to batch-screen.")
    parser.add_argument("--name-column", default="name",
                         help="Column name containing names in --file (default: 'name').")
    parser.add_argument("--output", default="screening_results.csv",
                         help="Output CSV path for batch screening (default: screening_results.csv).")
    parser.add_argument("--threshold", type=int, default=80,
                         help="Minimum similarity score (0-100) to report as a match (default: 80).")
    parser.add_argument("--refresh", action="store_true",
                         help="Force re-download of sanctions lists instead of using cache.")
    parser.add_argument("--demo", action="store_true",
                         help="Use small fictional demo data instead of live lists (for offline testing).")
    parser.add_argument("--eu-token", default=os.environ.get("EU_SANCTIONS_TOKEN"),
                         help="Optional EU FSF access token to also screen against the EU Consolidated List.")

    args = parser.parse_args()

    if not args.name and not args.file:
        parser.print_help()
        sys.exit(1)

    if args.file:
        screen_batch(args)
    else:
        screen_single(args)


if __name__ == "__main__":
    main()
