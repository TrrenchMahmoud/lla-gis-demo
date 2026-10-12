import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth import get_current_user
from .database import get_db
from .layers import layer_allowed
from .models import Role, User

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


router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/summary")
def summary(layer: str = Depends(guard), county: str | None = None, db: Session = Depends(get_db)):
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
       county: str | None = None, db: Session = Depends(get_db)):
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
          db: Session = Depends(get_db)):
    """Bounding box (lon/lat) of every feature whose group column matches this bucket."""
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
def timeline(layer: str = Depends(guard), county: str | None = None, db: Session = Depends(get_db)):
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
            user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Individual features ranked by area, each with its own bounding box for zooming.
    Only admins get the feature's real name - everyone else sees just its feature id."""
    schema, table = split_layer(layer)
    gc = geom_col(db, schema, table)
    idc = id_col_of(db, schema, table)
    cols = table_columns(db, schema, table)
    county_expr = '"county"' if "county" in cols else "NULL"
    lbl = label_expr(db, schema, table, idc, user.role == Role.admin)
    ae = area_expr(db, schema, table)
    limit = max(1, min(limit, 200))
    cond, params = county_condition(db, schema, table, county)
    where = f" WHERE {cond}" if cond else ""
    sql = text(
        f'SELECT "{idc}", {lbl} AS label, {ae} AS area_acres, {county_expr} AS county, '
        f'ST_XMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmin, '
        f'ST_YMin(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymin, '
        f'ST_XMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS xmax, '
        f'ST_YMax(ST_Transform(ST_Envelope("{gc}"), 4326)) AS ymax '
        f'FROM "{schema}"."{table}"{where} ORDER BY 3 DESC NULLS LAST LIMIT :lim OFFSET :off'
    )
    rows = db.execute(sql, {**params, "lim": limit, "off": max(0, offset)}).all()
    return {
        "idField": idc,
        "rows": [{"id": r[0], "label": r[1], "area_acres": float(r[2]), "county": r[3],
                  "bbox": {"xmin": r[4], "ymin": r[5], "xmax": r[6], "ymax": r[7]}} for r in rows],
    }
