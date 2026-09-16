#!/usr/bin/env python3
"""Build static/world.geo.json — the dashboard map's self-hosted basemap.

Protek used to draw the world map on raster tiles from a public provider. Every
keyless provider either rate-limits, watermarks, or (as OpenStreetMap did in
2026-09) blocks browser traffic outright under its tile usage policy, which
showed operators an "access blocked" grid instead of a map. The markers are the
data; the basemap is only there to locate them. So we ship our own outline and
depend on nobody.

Input is Natural Earth 1:110m land, as distributed in TopoJSON form by
world-atlas. Run:

    curl -sLo countries-110m.json \
      https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json
    python scripts/build_world_geojson.py countries-110m.json static/world.geo.json

Output is a single MultiPolygon Feature, ~75 KB, which is small enough to serve
from the app and fast enough to draw in one L.geoJSON call.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PRECISION = 2  # ~1.1 km at the equator; far finer than a 1:110m source resolves


def decode_arcs(topo: dict) -> list[list[list[float]]]:
    """Delta-decode TopoJSON's quantized arcs into absolute lon/lat pairs."""
    tx = topo["transform"]
    sx, sy = tx["scale"]
    dx, dy = tx["translate"]
    out = []
    for arc in topo["arcs"]:
        x = y = 0
        points = []
        for px, py in arc:
            x += px
            y += py
            points.append([x * sx + dx, y * sy + dy])
        out.append(points)
    return out


def stitch(arc_ids: list[int], arcs: list[list[list[float]]]) -> list[list[float]]:
    """Join a ring's arc references end to end.

    A negative index ~i means arc i traversed backwards. Consecutive arcs share
    an endpoint, so every arc after the first drops its first point.
    """
    ring: list[list[float]] = []
    for i in arc_ids:
        pts = arcs[~i][::-1] if i < 0 else arcs[i]
        ring.extend(pts if not ring else pts[1:])
    return ring


def split_at_antimeridian(ring: list[list[float]]) -> list[list[list[float]]]:
    """Cut a ring that straddles 180 deg, closing each half along its own edge.

    Natural Earth stores such a shape as one ring running ...+179, -179... An
    equirectangular renderer draws that jump as a filled band straight across
    the map — Russia's Chukotka does it twice, Fiji once.

    A ring is cyclic, so it is first rotated to begin just after a crossing: N
    crossings then yield exactly N closed parts, each starting and ending on the
    same +/-180 edge, where the closing segment is a vertical line hidden at the
    map's edge. Splitting without rotating instead leaves the first and last
    pieces open and closes them against each other, drawing a diagonal.

    Rings with a single crossing (Antarctica's bottom seam) are returned as-is —
    there is no second cut to pair with, and the seam sits below the viewport.
    """
    cuts = [k for k, (a, b) in enumerate(zip(ring, ring[1:])) if abs(b[0] - a[0]) > 180]
    if len(cuts) < 2:
        return [ring]

    body = ring[:-1] if ring[0] == ring[-1] else list(ring)
    body = body[cuts[0] + 1:] + body[:cuts[0] + 1]
    body.append(body[0])

    parts, cur = [], [body[0]]
    for a, b in zip(body, body[1:]):
        if abs(b[0] - a[0]) > 180:
            edge = 180.0 if a[0] > 0 else -180.0
            # latitude where the segment meets the edge, linear in unwrapped lon.
            # span is 0 when the segment runs exactly +180 -> -180, i.e. both
            # ends already sit on the edge and there is nothing to interpolate.
            span = (b[0] + 360 if a[0] > 0 else b[0] - 360) - a[0]
            lat = a[1] if span == 0 else round(
                a[1] + (b[1] - a[1]) * ((edge - a[0]) / span), PRECISION
            )
            cur.append([edge, lat])
            cur.append(cur[0])
            parts.append(cur)
            cur = [[-edge, lat], b]
        else:
            cur.append(b)
    if len(cur) > 3:
        cur.append(cur[0])
        parts.append(cur)
    return [p for p in parts if len(p) >= 4]


def main(src: Path, dst: Path) -> None:
    topo = json.loads(src.read_text())
    arcs = decode_arcs(topo)
    obj = topo["objects"]["countries"]

    polygons = []
    for geom in obj["geometries"]:
        shapes = (
            [geom["arcs"]] if geom["type"] == "Polygon" else geom["arcs"]
        )  # MultiPolygon is a list of Polygons
        for shape in shapes:
            rings = []
            for arc_ids in shape:
                ring = [
                    [round(x, PRECISION), round(y, PRECISION)]
                    for x, y in stitch(arc_ids, arcs)
                ]
                rings.extend(split_at_antimeridian(ring))
            if rings:
                polygons.append(rings)

    feature = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {"name": "land"},
                "geometry": {"type": "MultiPolygon", "coordinates": polygons},
            }
        ],
    }
    dst.write_text(json.dumps(feature, separators=(",", ":")))
    print(f"{dst}: {len(polygons)} polygons, {dst.stat().st_size} bytes")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
