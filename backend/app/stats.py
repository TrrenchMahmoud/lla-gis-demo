import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import get_current_user, require_role
from .database import get_db
from .features import require_feature
from .layers import layer_allowed
from .models import Role, User
from .schemas import OccupancyCheck

STAFF_ROLES = (Role.admin, Role.super_admin)

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LAYER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")

# columns that identify a specific feature by name - admin-only, never a "group by" bucket either
NAME_COLS = {"name", "label", "parcel_name", "title"}

# columns we never offer as a "group by" bucket in the breakdown chart
SKIP_GROUP_COLS = {
    "ogc_fid", "id", "gid", "fid", "ctid", "wkb_geometry", "geom", "geometry",
    "shape_leng", "shape_length", "shape_area", "area_acres",
} | NAME_COLS

_GEOM_COL_CACHE: dict[str, str] = {}
_COLS_CACHE: dict[str, list[str]] = {}


def split_layer(layer: str) -> tuple[str, str]:
    if not layer or not LAYER_RE.match(layer):
        raise HTTPException(400, "Invalid layer")
    schema, table = layer.split(".", 1)
    return schema, table


def table_exists(db: Session, schema: str, table: str) -> bool:
    row = db.execute(text(
        "SELECT 1 FROM geometry_columns WHERE f_table_schema = :s AND f_table_name = :t"
    ), {"s": schema, "t": table}).first()
    return bool(row)


def geom_col(db: Session, schema: str, table: str) -> str:
    """Look up the geometry column name from the catalog rather than assuming one."""
    key = f"{schema}.{table}"
    if key not in _GEOM_COL_CACHE:
        row = db.execute(text(
            "SELECT f_geometry_column FROM geometry_columns "
            "WHERE f_table_schema = :s AND f_table_name = :t"
        ), {"s": schema, "t": table}).first()
        col = row[0] if row and NAME_RE.match(row[0] or "") else "wkb_geometry"
        _GEOM_COL_CACHE[key] = col
    return _GEOM_COL_CACHE[key]


def table_columns(db: Session, schema: str, table: str) -> list[str]:
    key = f"{schema}.{table}"
    if key not in _COLS_CACHE:
        rows = db.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = :s AND table_name = :t ORDER BY ordinal_position"
        ), {"s": schema, "t": table}).all()
        _COLS_CACHE[key] = [r[0] for r in rows]
    return _COLS_CACHE[key]


def resolve_layer(db: Session, layer: str) -> tuple[str, str]:
    """Validate a layer id against the geometry_columns catalog before it ever reaches SQL."""
    schema, table = split_layer(layer)
    if not table_exists(db, schema, table):
        raise HTTPException(404, "Unknown layer")
    return schema, table


def area_expr(db: Session, schema: str, table: str) -> str:
    """SQL expression for a feature's area in acres: use area_acres if present, else compute it."""
    if "area_acres" in table_columns(db, schema, table):
        return 'COALESCE("area_acres", 0)'
    gc = geom_col(db, schema, table)
    return f'COALESCE(ST_Area(ST_Transform("{gc}", 3857)), 0) / 4046.8564224'


def id_col_of(db: Session, schema: str, table: str) -> str:
    cols = table_columns(db, schema, table)
    for cand in ("ogc_fid", "gid", "id", "fid"):
        if cand in cols:
            return cand
    return cols[0] if cols else "ctid"


def label_expr(db: Session, schema: str, table: str, id_col: str, admin: bool) -> str:
    """Admins see the feature's real name column, if it has one; everyone else just gets its id."""
    if admin:
        cols = table_columns(db, schema, table)
        for cand in ("name", "label", "parcel_name", "title"):
            if cand in cols:
                return f"COALESCE(NULLIF(TRIM(\"{cand}\"::text), ''), 'Feature ' || \"{id_col}\")"
    return f"'Feature ' || \"{id_col}\""


def county_condition(db: Session, schema: str, table: str, county: str | None) -> tuple[str | None, dict]:
    """SQL boolean fragment (no WHERE/AND keyword) to restrict rows to one county, if this layer has one."""
    if not county or "county" not in table_columns(db, schema, table):
        return None, {}
    return 'UPPER(TRIM("county"::text)) = UPPER(TRIM(:county))', {"county": county}


def guard(layer: str = "public.plsd", db: Session = Depends(get_db),
          user: User = Depends(get_current_user)) -> str:
    resolve_layer(db, layer)
    if not layer_allowed(db, user, f"/tiles/{layer}.json"):
        raise HTTPException(403, "No access to this layer")
    return layer


def resolve_county_param(county: str | None, user: User) -> str | None:
    """A county-scoped admin (User.county_scope set) is pinned to their own county no matter
    what the client asks for - the override is silent and server-side, not a UI restriction
    the client could just skip."""
    if user.role == Role.admin and getattr(user, "county_scope", None):
        return user.county_scope
    return county


router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary")
def summary(layer: str = Depends(guard), county: str | None = None, db: Session = Depends(get_db),
            user: User = Depends(get_current_user)):
    county = resolve_county_param(county, user)
    schema, table = split_layer(layer)
    cond, params = county_condition(db, schema, table, county)
    where = f" WHERE {cond}" if cond else ""
    sql = text(f'SELECT COUNT(*), COALESCE(SUM({area_expr(db, schema, table)}), 0) '
               f'FROM "{schema}"."{table}"{where}')
    r = db.execute(sql, params).one()
    return {"parcels": int(r[0]), "acres": float(r[1])}


@router.get("/groups")
def groups(layer: str = Depends(guard), db: Session = Depends(get_db)):
    """Which columns of this layer make sense as a 'group by' bucket for the breakdown chart."""
    schema, table = split_layer(layer)
    gc = geom_col(db, schema, table).lower()
    out = []
    for c in table_columns(db, schema, table):
        lc = c.lower()
        if lc in SKIP_GROUP_COLS or lc == gc or lc.startswith("shape_") or lc.endswith("_id"):
            continue
        out.append(c)
    return out


@router.get("/by")
def by(group: str, layer: str = Depends(guard), metric: str = "count", limit: int = 15,
       county: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    county = resolve_county_param(county, user)
    schema, table = split_layer(layer)
    if not NAME_RE.match(group) or group not in table_columns(db, schema, table):
        raise HTTPException(400, "Unsupported group column for this layer")
    if metric not in ("count", "area"):
        raise HTTPException(400, "Unsupported metric")
    val = "COUNT(*)" if metric == "count" else f"COALESCE(SUM({area_expr(db, schema, table)}), 0)"
    cond, params = county_condition(db, schema, table, county)
    where = f" WHERE {cond}" if cond else ""
    sql = text(
        f'SELECT COALESCE(NULLIF(TRIM("{group}"::text), \'\'), \'(blank)\') AS label, '
        f'{val} AS value FROM "{schema}"."{table}"{where} GROUP BY 1 ORDER BY 2 DESC LIMIT :n'
    )
    rows = db.execute(sql, {**params, "n": max(1, min(limit, 50))}).all()
    return [{"label": r[0], "value": float(r[1])} for r in rows]


@router.get("/bbox")
def bbox(group: str, value: str, layer: str = Depends(guard), county: str | None = None,
          db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Bounding box (lon/lat) of every feature whose group column matches this bucket."""
    county = resolve_county_param(county, user)
    schema, table = split_layer(layer)
    if not NAME_RE.match(group) or group not in table_columns(db, schema, table):
        raise HTTPException(400, "Unsupported group column for this layer")
    gc = geom_col(db, schema, table)
    cond, params = county_condition(db, schema, table, county)
    extra = f" AND {cond}" if cond else ""
    sql = text(
        f'SELECT ST_XMin(e), ST_YMin(e), ST_XMax(e), ST_YMax(e) FROM ('
        f'SELECT ST_Extent(ST_Transform("{gc}", 4326)) AS e FROM "{schema}"."{table}" '
        f"WHERE COALESCE(NULLIF(TRIM(\"{group}\"::text), ''), '(blank)') = :v{extra}"
        f') t'
    )
    row = db.execute(sql, {**params, "v": value}).first()
    if not row or row[0] is None:
        raise HTTPException(404, "No matching features")
    return {"xmin": row[0], "ymin": row[1], "xmax": row[2], "ymax": row[3]}


# Ordered by priority. ogr2ogr (shapefile -> PostGIS) truncates column names to 10
# characters, so "date_survey" becomes "date_surve" - both forms are listed here.
_NAMED_DATE_CANDIDATES = (
    "d_survey", "date_surve", "survey_date", "date_survey", "surv_date", "survey_dt",
    "dt_survey", "date_surveyed", "surveyed_on", "date_of_survey",
)
# Date-typed columns that name something OTHER than the survey itself (e.g. when a
# record was entered into the system) - only used as a last resort, since charting them
# means "records added per year", not "surveys per year".
_NON_SURVEY_DATE_NAMES = {"date_enter", "date_created", "created_at", "date_update", "updated_at", "entry_date"}
_DATE_SQL_TYPES = {"date", "timestamp without time zone", "timestamp with time zone"}
_YEAR_NUMERIC_TYPES = {"integer", "smallint", "bigint", "numeric"}
_TEXT_TYPES = {"character varying", "text", "char", "bpchar"}


def date_col_of(db: Session, schema: str, table: str) -> tuple[str | None, str | None]:
    """Find a usable survey/date column for the timeline chart.
    Returns (column, mode). mode is one of:
      "date"       - a real date/timestamp column, use EXTRACT(YEAR FROM ...)
      "year_number"- already a bare year number (e.g. 2019), cast straight to int
      "text_date"  - a date stored as plain text (common after a shapefile import,
                     e.g. "2019-05-02" or "05/02/2019" in a varchar column) - the
                     first 4-digit run in the text is pulled out as the year
    Checks known column names first, then a date/timestamp-typed column whose name
    contains "surv", then any other date-typed column, then a text column that looks
    date-ish, then a bare year-number column - each tier prefers a "survey"-named
    column over a generic one (like a record's creation date) within that tier."""
    rows = db.execute(text(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = :s AND table_name = :t"
    ), {"s": schema, "t": table}).all()
    col_types = {col: dtype for col, dtype in rows if NAME_RE.match(col)}

    def mode_for(col: str) -> str | None:
        dtype = col_types.get(col)
        if dtype in _DATE_SQL_TYPES:
            return "date"
        if dtype in _YEAR_NUMERIC_TYPES:
            return "year_number"
        if dtype in _TEXT_TYPES:
            return "text_date"
        return None

    for c in _NAMED_DATE_CANDIDATES:
        m = mode_for(c)
        if m:
            return c, m

    date_cols = [c for c, dt in col_types.items() if dt in _DATE_SQL_TYPES]
    for c in date_cols:
        if "surv" in c.lower():
            return c, "date"
    for c in date_cols:
        if c.lower() not in _NON_SURVEY_DATE_NAMES:
            return c, "date"

    text_date_cols = [c for c, dt in col_types.items() if dt in _TEXT_TYPES and ("dat" in c.lower())]
    for c in text_date_cols:
        if "surv" in c.lower():
            return c, "text_date"
    for c in text_date_cols:
        if c.lower() not in _NON_SURVEY_DATE_NAMES:
            return c, "text_date"

    for c, dt in col_types.items():
        lc = c.lower()
        if dt in _YEAR_NUMERIC_TYPES and ("year" in lc or lc in ("yr", "survey_yr")):
            return c, "year_number"
    return None, None


_YEAR_EXPR_BY_MODE = {
    "date": 'EXTRACT(YEAR FROM "{col}")::int',
    "year_number": '"{col}"::int',
    # First run of 4 digits found in the text, e.g. "05/02/2019" or "2019-05-02" -> 2019.
    # NULLIF+regexp_match guards rows whose text doesn't contain a year at all.
    "text_date": '''NULLIF((regexp_match("{col}", '\\d{{4}}'))[1], '')::int''',
}


@router.get("/timeline")
def timeline(layer: str = Depends(guard), county: str | None = None, db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    county = resolve_county_param(county, user)
    schema, table = split_layer(layer)
    date_col, mode = date_col_of(db, schema, table)
    if not date_col:
        return []
    cond, params = county_condition(db, schema, table, county)
    extra = f" AND {cond}" if cond else ""
    year_expr = _YEAR_EXPR_BY_MODE[mode].format(col=date_col)
    # A subquery + outer "y IS NOT NULL" catches every case where no year could be
    # pulled out - a genuinely NULL column, or (for text_date) a string with no digits.
    sql = text(
        f'SELECT y, COUNT(*) FROM ('
        f'  SELECT {year_expr} AS y FROM "{schema}"."{table}" WHERE "{date_col}" IS NOT NULL{extra}'
        f') t WHERE y IS NOT NULL GROUP BY y ORDER BY y'
    )
    rows = db.execute(sql, params).all()
    return [{"year": r[0], "parcels": int(r[1])} for r in rows]


@router.get("/parcels")
def parcels(limit: int = 15, offset: int = 0, layer: str = Depends(guard), county: str | None = None,
            q: str | None = None, min_acres: float | None = None, max_acres: float | None = None,
            user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Individual features ranked by area, each with its own bounding box for zooming.
    Only admins get the feature's real name - everyone else sees just its feature id.
    q searches the displayed label (name, for an admin - id, for everyone else) and the
    raw id; min_acres/max_acres restrict by the feature's area. Filtering happens in an
    outer query so it can match against the *displayed* label rather than a raw column."""
    county = resolve_county_param(county, user)
    schema, table = split_layer(layer)
    gc = geom_col(db, schema, table)
    idc = id_col_of(db, schema, table)
    cols = table_columns(db, schema, table)
    county_expr = '"county"' if "county" in cols else "NULL"
    lbl = label_expr(db, schema, table, idc, user.role in STAFF_ROLES)
    ae = area_expr(db, schema, table)
    is_filtering = bool(q) or min_acres is not None or max_acres is not None
    limit = max(1, min(limit, 500 if is_filtering else 200))
    cond, params = county_condition(db, schema, table, county)
    inner_where = f" WHERE {cond}" if cond else ""

    outer_conditions = []
    if q:
        outer_conditions.append('(label ILIKE :q OR CAST(id AS TEXT) ILIKE :q)')
        params["q"] = f"%{q.strip()}%"
    if min_acres is not None:
        outer_conditions.append('area_acres >= :min_acres')
        params["min_acres"] = min_acres
    if max_acres is not None:
        outer_conditions.append('area_acres <= :max_acres')
        params["max_acres"] = max_acres
    outer_where = f" WHERE {' AND '.join(outer_conditions)}" if outer_conditions else ""

    sql = text(
        f'SELECT id, label, area_acres, county, xmin, ymin, xmax, ymax FROM ('
        f'  SELECT "{idc}" AS id, {lbl} AS label, {ae} AS area_acres, {county_expr} AS county, '
        f'  ST_XMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmin, '
        f'  ST_YMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymin, '
        f'  ST_XMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmax, '
        f'  ST_YMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymax '
        f'  FROM "{schema}"."{table}"{inner_where}'
        f') t{outer_where} ORDER BY area_acres DESC NULLS LAST LIMIT :lim OFFSET :off'
    )
    rows = db.execute(sql, {**params, "lim": limit, "off": max(0, offset)}).all()
    return {
        "idField": idc,
        "rows": [{"id": r[0], "label": r[1], "area_acres": float(r[2]), "county": r[3],
                  "bbox": {"xmin": r[4], "ymin": r[5], "xmax": r[6], "ymax": r[7]}} for r in rows],
    }


@router.post("/check-occupancy")
def check_occupancy(payload: OccupancyCheck, layer: str = Depends(guard),
                     user: User = Depends(get_current_user), db: Session = Depends(get_db),
                     _: None = Depends(require_feature("occupancy_check"))):
    """Does a point, or the boundary of an area, fall inside (or overlap) any feature already
    mapped in this layer? A single point is a point-in-polygon test; 3+ points are treated as
    a closed area and checked for any overlap. Coordinates are [lng, lat] in WGS84 (EPSG:4326)."""
    points = payload.points
    if len(points) < 1:
        raise HTTPException(400, "Provide at least one coordinate")
    if any(len(p) != 2 for p in points):
        raise HTTPException(400, "Each coordinate must be a [lng, lat] pair")
    schema, table = split_layer(layer)
    gc = geom_col(db, schema, table)
    idc = id_col_of(db, schema, table)
    lbl = label_expr(db, schema, table, idc, user.role in STAFF_ROLES)
    ae = area_expr(db, schema, table)
    cols = table_columns(db, schema, table)
    county_expr = '"county"' if "county" in cols else "NULL"

    if len(points) == 1:
        lng, lat = points[0]
        if not (-180 <= lng <= 180 and -90 <= lat <= 90):
            raise HTTPException(400, "Coordinate out of range - expected [lng, lat]")
        query_geom_sql = "ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)"
        params = {"lng": lng, "lat": lat}
        predicate = f'ST_Contains(ST_Transform("{gc}", 4326), {query_geom_sql})'
    else:
        ring = [tuple(p) for p in points]
        if ring[0] != ring[-1]:
            ring = ring + [ring[0]]
        for lng, lat in ring:
            if not (-180 <= lng <= 180 and -90 <= lat <= 90):
                raise HTTPException(400, "Coordinate out of range - expected [lng, lat]")
        wkt = "POLYGON((" + ",".join(f"{lng} {lat}" for lng, lat in ring) + "))"
        query_geom_sql = "ST_SetSRID(ST_GeomFromText(:wkt), 4326)"
        params = {"wkt": wkt}
        predicate = f'ST_Intersects(ST_Transform("{gc}", 4326), {query_geom_sql})'

    sql = text(
        f'SELECT "{idc}" AS id, {lbl} AS label, {ae} AS area_acres, {county_expr} AS county, '
        f'ST_XMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmin, '
        f'ST_YMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymin, '
        f'ST_XMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmax, '
        f'ST_YMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymax '
        f'FROM "{schema}"."{table}" WHERE {predicate} LIMIT 25'
    )
    rows = db.execute(sql, params).all()
    return {
        "layer": layer,
        "matches": [{"id": r[0], "label": r[1], "area_acres": float(r[2]), "county": r[3],
                     "bbox": {"xmin": r[4], "ymin": r[5], "xmax": r[6], "ymax": r[7]}} for r in rows],
    }


def known_layers(db: Session) -> list[tuple[str, str]]:
    """Every spatial table in the public schema - the dynamic layer list, discovered the same
    way pg_tileserv discovers it, rather than a hardcoded list that would drift out of date."""
    rows = db.execute(text(
        "SELECT f_table_schema, f_table_name FROM geometry_columns WHERE f_table_schema = 'public' "
        "ORDER BY f_table_name"
    )).all()
    return [(r[0], r[1]) for r in rows if NAME_RE.match(r[1])]


@router.get("/overlaps")
def overlaps(limit: int = 200, county: str | None = None, db: Session = Depends(get_db),
             user: User = Depends(require_role(*STAFF_ROLES)),
             _: None = Depends(require_feature("overlap_report"))):
    """Cross-layer QA report: flags any two mapped features - in the same layer or across two
    different layers - whose boundaries genuinely overlap (more than a sliver, to avoid flagging
    parcels that merely share a boundary line). Usually means a duplicate entry or a conflicting
    allocation and is worth a human looking at it. Capped at `limit` pairs, worst overlap first."""
    county = resolve_county_param(county, user)
    layers = known_layers(db)
    results: list[dict] = []
    for i in range(len(layers)):
        for j in range(i, len(layers)):
            s1, t1 = layers[i]
            s2, t2 = layers[j]
            same = (s1, t1) == (s2, t2)
            try:
                gc1, gc2 = geom_col(db, s1, t1), geom_col(db, s2, t2)
                id1, id2 = id_col_of(db, s1, t1), id_col_of(db, s2, t2)
                cols1, cols2 = table_columns(db, s1, t1), table_columns(db, s2, t2)
            except Exception:
                continue
            cty1 = '"a"."county"' if "county" in cols1 else "NULL"
            cty2 = '"b"."county"' if "county" in cols2 else "NULL"
            params: dict = {}
            county_clause = ""
            if county:
                conds = []
                if "county" in cols1:
                    conds.append('UPPER(TRIM("a"."county"::text)) = UPPER(TRIM(:county))')
                if "county" in cols2:
                    conds.append('UPPER(TRIM("b"."county"::text)) = UPPER(TRIM(:county))')
                if conds:
                    county_clause = " AND (" + " OR ".join(conds) + ")"
                    params["county"] = county
            id_guard = f'"a"."{id1}" < "b"."{id1}"' if same else "TRUE"
            a_geom = f'ST_Transform("a"."{gc1}", 4326)'
            b_geom = f'ST_Transform("b"."{gc2}", 4326)'
            sql = text(
                f'SELECT "a"."{id1}" AS id_a, "b"."{id2}" AS id_b, '
                f'ST_Area(ST_Transform(ST_Intersection({a_geom}, {b_geom}), 3857)) / 4046.8564224 AS overlap_acres, '
                f'{cty1} AS county_a, {cty2} AS county_b '
                f'FROM "{s1}"."{t1}" a JOIN "{s2}"."{t2}" b '
                f'  ON ST_Intersects({a_geom}, {b_geom}) AND {id_guard}{county_clause} '
                f'WHERE ST_Area(ST_Intersection({a_geom}, {b_geom})) > 0.0000005 '
                f'ORDER BY overlap_acres DESC LIMIT :lim'
            )
            try:
                rows = db.execute(sql, {**params, "lim": limit}).all()
            except Exception:
                continue
            for r in rows:
                results.append({
                    "layer_a": f"{s1}.{t1}", "id_a": r[0], "county_a": r[3],
                    "layer_b": f"{s2}.{t2}", "id_b": r[1], "county_b": r[4],
                    "overlap_acres": round(float(r[2]), 3),
                })
    results.sort(key=lambda x: -x["overlap_acres"])
    return {"checked_layers": [f"{s}.{t}" for s, t in layers], "pairs": results[:limit]}
