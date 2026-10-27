#!/usr/bin/env python3
"""Append sourced events to the threat-map feed.

Reads a JSON list of events, geocodes each place with OpenStreetMap
Nominatim, and updates events.geojson plus events.csv.

Input objects require: place, what, when_utc, source, status, category,
target_type. target_type may be null. Optional coord_precision is "exact"
or "approximate"; optional coord_note is appended for approximate values.
If coord_precision is omitted, a place ending in "(approximate)" or
"(approximate: note)" is stored as approximate and that parenthesis is not
sent to the geocoder. A different parenthesis that names a locality, such
as "(Desnianskyi district)", is searched first as a more specific query.
A parenthesis that starts with "also", "including", "near", or "and" stays
in the place text and is not geocoded as its own point. If the full place
string returns no Nominatim hits, one shorter query is tried: the leading
locality with a trailing word such as County or District removed, plus the
country. A hit from that shorter query is stored as approximate, with a
note naming the match, in the same form as "approximate: Houthi-held Yemen".
The words "closure order" are stored as the category "closure".

added_utc is the UTC time the row is first inserted, formatted
YYYY-MM-DDTHH:MM:SSZ. Input cannot set it. A later re-geocode or edit of
the same source+place+what leaves the original stamp in place. Feeds are
rewritten newest added_utc first.

Nominatim is called at most once per second with a custom User-Agent.
Only coordinates returned by Nominatim are stored. An empty result, a
distance/bearing offset (a gazetteer cannot resolve "63nm SE of" a port),
or a hit that is only a road name is written with null geometry and empty
lat/lon. The script never invents a coordinate and does not substitute a
nearby city. A transport or HTTP failure aborts before the feed is written.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = (
    "threat-map/1.0 "
    "(https://github.com/SimpleAdoptionRegistry/threat-map; public event feed)"
)
ROOT = Path(__file__).resolve().parent.parent
CATEGORIES = {
    "strike",
    "shipping",
    "military_movement",
    "closure",
    "protest",
    "infrastructure",
}
PROP_KEYS = [
    "id",
    "category",
    "place",
    "what",
    "when_utc",
    "source",
    "status",
    "target_type",
    "coord_precision",
    "added_utc",
]
CSV_FIELDS = PROP_KEYS + ["lat", "lon"]
REQUIRED = [
    "place",
    "what",
    "when_utc",
    "source",
    "status",
    "category",
    "target_type",
]
APPROX_RE = re.compile(
    r"\s*\(approximate(?::\s*([^)]*))?\)\s*",
    re.IGNORECASE,
)
NOTE_PAREN_RE = re.compile(
    r"\s*\((?:also|including|incl\.?|near|and)\b[^)]*\)\s*",
    re.IGNORECASE,
)
QUALIFIER_RE = re.compile(r"\(([^)]*)\)")
CATEGORY_ALIASES = {
    "closure order": "closure",
}
OFFSET_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*(?:nm|nmi|km|kilometers|nautical miles)\b",
    re.IGNORECASE,
)
ROAD_HINTS = ("road", "street", "highway", "avenue", "lane", "bridge")
AREA_WORDS = ("district", "county", "raion", "oblast", "governorate", "province", "prefecture", "municipality")
AREA_PLACE_TYPES = {
    "city",
    "town",
    "village",
    "municipality",
    "county",
    "state",
    "city_district",
    "borough",
    "suburb",
    "quarter",
    "region",
}
MIN_INTERVAL_SEC = 1.05


class GeocodeError(RuntimeError):
    """Nominatim could not be queried. The feed must not be rewritten."""


_last_request = 0.0


def load_input(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        data = data["events"]
    if not isinstance(data, list):
        raise SystemExit("Input JSON must be a list of events, or {\"events\": [...]}")
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise SystemExit(f"Event {index} is not an object")
    return data


def load_collection(path: Path) -> dict:
    if not path.exists():
        return {"type": "FeatureCollection", "features": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("type") != "FeatureCollection" or not isinstance(data.get("features"), list):
        raise SystemExit(f"{path} is not a GeoJSON FeatureCollection")
    return data


def dedupe_key(source: str, place: str, what: str) -> tuple[str, str, str]:
    def norm(value: str) -> str:
        return " ".join(value.split()).casefold()

    return (norm(source), norm(place), norm(what))


def coord_precision_for(event: dict, place: str) -> str:
    explicit = event.get("coord_precision")
    if explicit is not None and str(explicit).strip():
        precision = str(explicit).strip()
        note = event.get("coord_note")
        if precision == "approximate" and note and str(note).strip():
            return f"approximate: {str(note).strip()}"
        if precision not in {"exact", "approximate"} and not precision.startswith("approximate:"):
            raise SystemExit(
                f"coord_precision for {place!r} must be 'exact' or 'approximate'"
            )
        return precision
    match = APPROX_RE.search(place)
    if not match:
        return "exact"
    note = (match.group(1) or "").strip()
    if note:
        return f"approximate: {note}"
    return "approximate"


def geocode_query(place: str) -> str:
    cleaned = APPROX_RE.sub(" ", place)
    return " ".join(cleaned.split())


def canonical_category(category: str) -> str:
    compact = " ".join(category.split()).casefold()
    return CATEGORY_ALIASES.get(compact, category.strip())


LOCALITY_TYPE_WORDS = {
    "county",
    "district",
    "raion",
    "oblast",
    "governorate",
    "province",
    "prefecture",
    "municipality",
    "city",
    "town",
    "village",
    "gun",
    "guyok",
    "region",
    "subdistrict",
    "borough",
    "crossing",
    "border",
    "checkpoint",
    "terminal",
    "station",
    "port",
    "bridge",
    "camp",
    "base",
    "airport",
    "airbase",
    "airfield",
}


def shorter_queries(place: str) -> list[str]:
    """Locality plus country, for when the full place string returns nothing.

    "Kaepung County, North Korea" becomes "Kaepung, North Korea".
    "Nasib border crossing, Daraa, Syria" becomes "Nasib, Syria".
    "Al-Mawasi, Khan Yunis, Gaza Strip" becomes "Al-Mawasi, Gaza Strip".
    The result is not used until the full string has no Nominatim hits.
    """
    full = " ".join(QUALIFIER_RE.sub(" ", NOTE_PAREN_RE.sub(" ", geocode_query(place))).split())
    parts = [part.strip() for part in full.split(",") if part.strip()]
    if len(parts) < 2:
        return []
    words = parts[0].split()
    while words and words[-1].casefold().strip(".") in LOCALITY_TYPE_WORDS:
        words.pop()
    locality = " ".join(words).strip()
    if not locality:
        return []
    if locality.casefold() == parts[0].casefold() and len(parts) < 3:
        return []
    query = f"{locality}, {parts[-1]}"
    if query.casefold() == full.casefold():
        return []
    return [query]


def match_label(hit: dict, query: str) -> str:
    """Short place label for an approximate note, without the searched country."""
    country = last_clause(query)
    parts = [part.strip() for part in str(hit.get("display_name") or "").split(",") if part.strip()]
    if country and parts and parts[-1].casefold() == country.casefold():
        parts = parts[:-1]
    label = ", ".join(parts)
    if not label:
        label = str(hit.get("name") or "").strip()
    return label


def query_candidates(place: str) -> list[str]:
    """Nominatim queries for a place, most specific first.

    Coordinates still come only from a hit on one of these queries.
    """
    without_approx = " ".join(APPROX_RE.sub(" ", place).split())
    without_notes = " ".join(NOTE_PAREN_RE.sub(" ", without_approx).split())
    qualifiers = [part.strip() for part in QUALIFIER_RE.findall(without_notes) if part.strip()]
    base = " ".join(QUALIFIER_RE.sub(" ", without_notes).split())
    candidates: list[str] = []

    def add(query: str) -> None:
        query = " ".join(query.split()).strip(" ,")
        if query and query.casefold() not in {item.casefold() for item in candidates}:
            candidates.append(query)

    for qualifier in qualifiers:
        if base:
            add(f"{qualifier}, {base}")
    add(base)
    add(without_approx)
    return candidates


def make_id(source: str, place: str, what: str, used: set[str]) -> str:
    digest = sha256(f"{source}|{place}|{what}".encode("utf-8")).hexdigest()[:10]
    candidate = f"tm-{digest}"
    if candidate not in used:
        return candidate
    number = 2
    while f"{candidate}-{number}" in used:
        number += 1
    return f"{candidate}-{number}"


def throttle() -> None:
    global _last_request
    if _last_request:
        wait = MIN_INTERVAL_SEC - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
    _last_request = time.monotonic()


def nominatim_search(query: str) -> list[dict]:
    params = urllib.parse.urlencode(
        {
            "q": query,
            "format": "jsonv2",
            "limit": "5",
            "accept-language": "en",
            "addressdetails": "1",
        }
    )
    request = urllib.request.Request(
        f"{NOMINATIM_URL}?{params}",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Language": "en",
        },
    )
    delay = 2.0
    last_error: Exception | None = None
    for attempt in range(3):
        throttle()
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                payload = response.read().decode("utf-8")
            parsed = json.loads(payload)
            if not isinstance(parsed, list):
                raise GeocodeError(f"Nominatim returned {type(parsed).__name__}, not a list")
            return parsed
        except GeocodeError:
            raise
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            if attempt == 2:
                break
        time.sleep(delay)
        delay *= 2
    raise GeocodeError(f"Nominatim request failed for {query!r}: {last_error}")


def usable_hit(hit: dict) -> tuple[float, float] | None:
    try:
        lat = round(float(hit["lat"]), 6)
        lon = round(float(hit["lon"]), 6)
    except (KeyError, TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return lat, lon


def last_clause(query: str) -> str | None:
    parts = [part.strip() for part in query.split(",") if part.strip()]
    if len(parts) < 2:
        return None
    return parts[-1]


def asks_for_area(query: str) -> bool:
    tokens = set(re.findall(r"[a-z0-9']+", query.casefold()))
    return bool(tokens & set(AREA_WORDS))


def is_area_hit(hit: dict) -> bool:
    category = str(hit.get("category") or "").casefold()
    kind = str(hit.get("type") or "").casefold()
    if category == "boundary" and kind == "administrative":
        return True
    return category == "place" and kind in AREA_PLACE_TYPES


def area_followup(query: str, hits: list[dict]) -> str | None:
    """One extra query for the admin area named on a building hit.

    The name comes from Nominatim's address for that hit. A district query
    uses city_district; a county query uses county. The result is kept only
    when it is itself an area.
    """
    folded = query.casefold()
    if "county" in folded:
        keys = ("county", "state", "region")
    elif "district" in folded or "raion" in folded:
        keys = ("city_district", "county", "state")
    else:
        keys = ("state", "county", "region", "city_district")
    tail = ", ".join(part.strip() for part in query.split(",")[1:] if part.strip())
    for hit in hits:
        address = hit.get("address") if isinstance(hit.get("address"), dict) else {}
        for key in keys:
            name = str(address.get(key) or "").strip()
            if not name:
                continue
            follow = f"{name}, {tail}" if tail else name
            follow = " ".join(follow.split())
            if follow.casefold() != folded:
                return follow
    return None


def hit_is_usable(query: str, hit: dict) -> bool:
    """True when this Nominatim hit is a coordinate for the queried place.

    Road-name matches are rejected unless the place text is itself a road.
    When the place has a comma, the last clause (country or city) has to
    appear in the result label so a same-named place in another country
    is not kept.
    """
    if usable_hit(hit) is None:
        return False
    category = str(hit.get("category") or "").casefold()
    query_cf = query.casefold()
    if category == "highway" and not any(hint in query_cf for hint in ROAD_HINTS):
        return False
    clause = last_clause(query)
    if clause and clause.casefold() not in str(hit.get("display_name") or "").casefold():
        return False
    return True


def geocode_place(place: str) -> tuple[tuple[float, float] | None, str, str | None]:
    """Return ((lat, lon) or None, reason, approximate note).

    reason is "ok", "short", "no_result", or "offset". "short" means the
    full place string returned no hits and a locality-plus-country query
    matched. Transport failures raise.
    """
    candidates = query_candidates(place)
    if not candidates:
        print(f"UNLOCATED\t{place}\tno_result\tquery=", file=sys.stderr)
        return None, "no_result", None
    if OFFSET_RE.search(place):
        results = nominatim_search(candidates[0])
        display = results[0].get("display_name", "") if results else ""
        coords = usable_hit(results[0]) if results else None
        print(
            f"UNLOCATED\t{place}\toffset\tdisplay={display}\tignored_latlon={coords}",
            file=sys.stderr,
        )
        return None, "offset", None
    seen_queries: set[str] = set()
    full_string_had_hits = False
    for query in candidates:
        found, results, _label = _geocode_query(place, query, seen_queries)
        if results:
            full_string_had_hits = True
        if found is not None:
            return found, "ok", None
        if not asks_for_area(query):
            continue
        follow = area_followup(query, results)
        if not follow or follow.casefold() in seen_queries:
            continue
        found, follow_results, _label = _geocode_query(place, follow, seen_queries, area_only=True)
        if follow_results:
            full_string_had_hits = True
        if found is not None:
            return found, "ok", None
    if not full_string_had_hits:
        for query in shorter_queries(place):
            found, _results, label = _geocode_query(place, query, seen_queries)
            if found is not None:
                return found, "short", label or None
    tried = candidates + shorter_queries(place)
    print(f"UNLOCATED\t{place}\tno_result\tquery={' | '.join(tried)}", file=sys.stderr)
    return None, "no_result", None


def _geocode_query(
    place: str,
    query: str,
    seen_queries: set[str],
    area_only: bool | None = None,
) -> tuple[tuple[float, float] | None, list[dict], str]:
    if query.casefold() in seen_queries:
        return None, [], ""
    seen_queries.add(query.casefold())
    require_area = asks_for_area(query) if area_only is None else area_only
    results = nominatim_search(query)
    for hit in results:
        display = hit.get("display_name", "")
        if not hit_is_usable(query, hit):
            print(
                f"REJECT\t{place}\t{hit.get('category')}/{hit.get('type')}\t{display}",
                file=sys.stderr,
            )
            continue
        if require_area and not is_area_hit(hit):
            print(
                f"REJECT\t{place}\tnot_area\t{hit.get('category')}/{hit.get('type')}\t{display}",
                file=sys.stderr,
            )
            continue
        coords = usable_hit(hit)
        if coords is None:
            continue
        lat, lon = coords
        print(
            f"GEOCODED\t{place}\t{lat:.6f}\t{lon:.6f}\tquery={query}\t{display}",
            file=sys.stderr,
        )
        return (lat, lon), results, match_label(hit, query)
    return None, results, ""


def new_feature(event: dict, used_ids: set[str], added_utc: str) -> dict:
    missing = [key for key in REQUIRED if key not in event]
    if missing:
        raise SystemExit(f"Event missing {missing}: {event.get('place')!r}")
    place = str(event["place"]).strip()
    what = str(event["what"]).strip()
    source = str(event["source"]).strip()
    when_utc = str(event["when_utc"]).strip()
    status = str(event["status"]).strip()
    category = canonical_category(str(event["category"]))
    if not place or not what or not source or not when_utc or not status:
        raise SystemExit(f"Event has an empty required string: {place!r}")
    if category not in CATEGORIES:
        raise SystemExit(
            f"Unknown category {category!r} for {place!r}. Expected one of {sorted(CATEGORIES)}"
        )
    target = event["target_type"]
    if target is not None:
        target = str(target).strip() or None
    feature_id = str(event["id"]).strip() if event.get("id") else make_id(source, place, what, used_ids)
    if feature_id in used_ids:
        raise SystemExit(f"Duplicate id {feature_id}")
    return {
        "type": "Feature",
        "geometry": None,
        "properties": {
            "id": feature_id,
            "category": category,
            "place": place,
            "what": what,
            "when_utc": when_utc,
            "source": source,
            "status": status,
            "target_type": target,
            "coord_precision": coord_precision_for(event, place),
            "added_utc": added_utc,
        },
    }


def apply_coordinates(feature: dict, coords: tuple[float, float] | None) -> None:
    if coords is None:
        feature["geometry"] = None
        return
    lat, lon = coords
    feature["geometry"] = {"type": "Point", "coordinates": [lon, lat]}


def sort_newest_first(features: list[dict]) -> list[dict]:
    """Newest added_utc first. Equal stamps keep their existing order."""
    return sorted(
        features,
        key=lambda feature: str((feature.get("properties") or {}).get("added_utc") or ""),
        reverse=True,
    )


def write_geojson(path: Path, collection: dict) -> None:
    path.write_text(
        json.dumps(collection, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def feature_lat_lon(feature: dict) -> tuple[str, str]:
    geometry = feature.get("geometry")
    if not geometry or geometry.get("type") != "Point":
        return "", ""
    coordinates = geometry.get("coordinates")
    if not isinstance(coordinates, list) or len(coordinates) < 2:
        return "", ""
    lon, lat = coordinates[0], coordinates[1]
    if lat is None or lon is None:
        return "", ""
    return (format_coord(lat), format_coord(lon))


def format_coord(value: float) -> str:
    return f"{float(value):.6f}".rstrip("0").rstrip(".")


def write_csv(path: Path, features: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for feature in features:
            props = feature.get("properties") or {}
            lat, lon = feature_lat_lon(feature)
            row = {key: props.get(key) for key in PROP_KEYS}
            if row["target_type"] is None:
                row["target_type"] = ""
            row["lat"] = lat
            row["lon"] = lon
            writer.writerow(row)


def existing_keys(features: list[dict]) -> set[tuple[str, str, str]]:
    keys = set()
    for feature in features:
        props = feature.get("properties") or {}
        keys.add(dedupe_key(str(props.get("source", "")), str(props.get("place", "")), str(props.get("what", ""))))
    return keys


def existing_ids(features: list[dict]) -> set[str]:
    ids = set()
    for feature in features:
        props = feature.get("properties") or {}
        if props.get("id"):
            ids.add(str(props["id"]))
    return ids


def add_events(input_path: Path, geojson_path: Path, csv_path: Path) -> int:
    incoming = load_input(input_path)
    collection = load_collection(geojson_path)
    features = collection["features"]
    keys = existing_keys(features)
    used_ids = existing_ids(features)
    added_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    added = 0
    skipped = 0
    unlocated: list[tuple[str, str]] = []
    original_stamps = {
        id(feature): str((feature.get("properties") or {}).get("added_utc") or "")
        for feature in features
    }

    pending: list[dict] = []
    for event in incoming:
        event = dict(event)
        # Insert time is owned by the feed. Callers cannot stamp or restamp a row.
        event.pop("added_utc", None)
        key = dedupe_key(str(event.get("source", "")), str(event.get("place", "")), str(event.get("what", "")))
        if key in keys:
            skipped += 1
            print(
                f"SKIP\t{event.get('place')}\tduplicate source+place+what; added_utc kept",
                file=sys.stderr,
            )
            continue
        feature = new_feature(event, used_ids, added_utc)
        keys.add(key)
        used_ids.add(feature["properties"]["id"])
        pending.append(feature)

    # Geocode only after validation, and only write the feed if every
    # Nominatim call either returns a result or a clean miss.
    for feature in pending:
        place = feature["properties"]["place"]
        coords, reason, note = geocode_place(place)
        apply_coordinates(feature, coords)
        if reason == "short":
            precision = str(feature["properties"].get("coord_precision") or "")
            if not precision.startswith("approximate:"):
                feature["properties"]["coord_precision"] = (
                    f"approximate: {note}" if note else "approximate"
                )
        if coords is None:
            unlocated.append((place, reason))
        features.append(feature)
        added += 1

    for feature, stamp in (
        (feature, original_stamps[id(feature)])
        for feature in features
        if id(feature) in original_stamps
    ):
        if str((feature.get("properties") or {}).get("added_utc") or "") != stamp:
            raise SystemExit("Refusing to overwrite added_utc on an existing event")

    features = sort_newest_first(features)
    collection["type"] = "FeatureCollection"
    collection["features"] = features
    write_geojson(geojson_path, collection)
    write_csv(csv_path, features)
    print(
        f"Added {added}, skipped {skipped} duplicate(s), "
        f"unlocated {len(unlocated)}. Wrote {geojson_path.name} and {csv_path.name}."
    )
    for place, reason in unlocated:
        print(f"Unlocated: {place} ({reason})")
    return added


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Geocode and append events to the threat-map feed.")
    parser.add_argument("input", type=Path, help="JSON file of new events")
    parser.add_argument("--geojson", type=Path, default=ROOT / "events.geojson")
    parser.add_argument("--csv", type=Path, default=ROOT / "events.csv")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.input.is_file():
        raise SystemExit(f"Input file not found: {args.input}")
    add_events(args.input, args.geojson, args.csv)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GeocodeError as exc:
        print(f"ERROR\t{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
