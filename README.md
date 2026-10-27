# Threat map

Static feed of sourced security events, plus a Leaflet map. GitHub Pages serves this site from the **root of `main`**. There is no build step.

## Feeds

- Map: https://simpleadoptionregistry.github.io/threat-map/
- GeoJSON: https://simpleadoptionregistry.github.io/threat-map/events.geojson
- CSV: https://simpleadoptionregistry.github.io/threat-map/events.csv

`events.geojson` is a GeoJSON FeatureCollection. Each feature is a Point `[lon, lat]`, or `geometry: null` when the place could not be geocoded. Properties are `id`, `category`, `place`, `what`, `when_utc`, `source`, `status`, `target_type`, `coord_precision`, `added_utc`.

`events.csv` has those same columns plus `lat` and `lon`. Unlocated rows leave `lat` and `lon` empty.

`added_utc` is when the row was first written to the feed, in UTC, such as `2026-10-27T01:15:22Z`. The script sets it at insert. Re-geocoding or editing the same `source` + `place` + `what` does not change it. Both files are sorted newest `added_utc` first. Consumers can filter on `added_utc` greater than their last pull and ignore rows they already have.

Categories used by the map: `strike`, `shipping`, `military_movement`, `closure`, `protest`, `infrastructure`.

`coord_precision` is `exact`, `approximate`, or `approximate: <note>`. `exact` means Nominatim matched the place name. It does not mean the coordinate was surveyed on the ground. Region and waterway hits are the gazetteer’s representative point. `status` is the sourcing label from the input (`confirmed`, `claim`, or a short qualifier such as `confirmed (toll is claim)`).

## Add events

Put new events in a JSON file. The file may be a list, or an object with an `events` list. Required fields:

| Field | Notes |
| --- | --- |
| `place` | Geocoded as written. `(approximate)` or `(approximate: note)` sets `coord_precision` and is removed from the geocoder query only. |
| `what` | What happened. |
| `when_utc` | When it happened, kept as supplied (ISO UTC when the source has one). |
| `source` | URL of the report. |
| `status` | `confirmed`, `claim`, or a short qualifier. |
| `category` | One of the categories above. |
| `target_type` | Short label, or `null`. |

Optional: `coord_precision` (`exact` or `approximate`) and `coord_note`.

```bash
python3 scripts/add_events.py path/to/new_events.json
```

The script uses only the Python standard library. It:

1. Skips any event whose `source` + `place` + `what` is already in the feed, and leaves that row's `added_utc` as it was. New rows are stamped at insert time. An `added_utc` in the input file is ignored.
2. Geocodes each new `place` with [OpenStreetMap Nominatim](https://nominatim.openstreetmap.org/) at one request per second, with a custom User-Agent identifying this repo. A parenthesis that names a locality, such as `(Desnianskyi district)`, is tried first as a more specific query. A parenthesis that starts with `also`, `including`, `near`, or `and` stays in the place text and does not become a second point. `closure order` is stored as the category `closure`.
3. Appends new features to `events.geojson`.
4. Regenerates `events.csv` from the GeoJSON.

Coordinates are copied only from a Nominatim hit for that place string. If Nominatim returns nothing usable, the event is still appended, with null geometry and empty `lat`/`lon`. Three cases count as unusable, and the script does not fill in a nearby city or a coordinate of its own:

- No result.
- The place is a distance and bearing from somewhere else (for example `63nm SE of Al-Faw`). A hit on the reference port would be a different location.
- The hit is only a road, unless the place text itself names a road. A comma-separated place also has to mention its last clause (usually the country or city) in the result label.
- The place names a district, county, or similar area, and the hit is a building or office. If that hit's address names the surrounding area, the script looks the area up once and keeps the point only when Nominatim returns the area itself.
- The full place string returns no hits. The script then tries the leading locality plus the country, with a trailing word such as County, District, or crossing removed (`Kaepung County, North Korea` becomes `Kaepung, North Korea`; `Nasib border crossing, Daraa, Syria` becomes `Nasib, Syria`; `Al-Mawasi, Khan Yunis, Gaza Strip` becomes `Al-Mawasi, Gaza Strip`). A hit from that shorter query is stored as `approximate: <matched place>`, the same form as `approximate: Houthi-held Yemen`. A shortened hit has to still name the place, including an old or alternate name Nominatim still returns. A bare direction word is not queried on its own, so `Southern Bridge, Kyiv, Ukraine` is retried as `Southern Bridge, Ukraine` rather than `Southern, Ukraine`.

If Nominatim cannot be reached, the script exits without rewriting the feed.

The seed loaded for this feed is `scripts/seed_events.json`. Running it again is safe; those rows are already deduped.

## GitHub Pages

Pages has to be enabled once in the repository settings:

**Settings → Pages → Build and deployment → Deploy from a branch → `main` → `/ (root)` → Save.**

Until that is saved, the feed URLs above will not resolve. This repo includes `.nojekyll` so Pages serves the HTML, GeoJSON, and CSV as static files.
