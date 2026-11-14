from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard_shared import SEVERITY_ORDER
from dashboard_views import (
    render_ai_comparison,
    render_bounty,
    render_overview,
    render_preventability,
    render_trends,
)
from sidebar_navigation import render_sidebar_links
from vuln_classification import master_map


REQUIRED_COLUMNS = {
    "program",
    "vuln_type",
    "substate",
    "severity",
    "bounty",
    "submitted_at",
    "disclosed_at",
}


def prepare_data(raw: pd.DataFrame) -> pd.DataFrame:
    missing_columns = REQUIRED_COLUMNS.difference(raw.columns)
    if missing_columns:
        raise ValueError(
            "The uploaded data is missing required columns: "
            + ", ".join(sorted(missing_columns))
        )

    df = raw.copy().dropna(subset=["submitted_at"])
    df["raw_vuln_type"] = df["vuln_type"]
    df["submitted_at"] = pd.to_datetime(
        df["submitted_at"], utc=True, errors="coerce"
    ).dt.tz_localize(None)
    df["disclosed_at"] = pd.to_datetime(
        df["disclosed_at"], utc=True, errors="coerce"
    ).dt.tz_localize(None)
    df = df.dropna(subset=["submitted_at"])
    df["report_year"] = df["submitted_at"].dt.year

    bounty_labels = df["bounty"].astype("string").str.strip()
    df["bounty_hidden"] = bounty_labels.str.casefold().eq("hidden").fillna(False)
    df["bounty_missing"] = df["bounty"].isna() | bounty_labels.eq("").fillna(False)
    df["bounty"] = pd.to_numeric(df["bounty"], errors="coerce")
    df["vuln_type"] = df["vuln_type"].replace(master_map)
    df["valid_report"] = (
        df["substate"].fillna("").str.casefold().isin({"informative", "resolved"})
    )
    df["severity"] = df["severity"].str.casefold()
    return df


st.title("HackerOne Vulnerability Landscape")
st.caption("An interactive view of publicly disclosed HackerOne reports.")

try:
    data = prepare_data(pd.read_csv("data/h1reports.csv"))
except (OSError, pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
    st.error(f"Could not load the report data: {error}")
    st.stop()

years = sorted(data["report_year"].dropna().astype(int).unique().tolist())
available_severities = [
    severity for severity in SEVERITY_ORDER if severity in set(data["severity"].dropna())
]
available_substates = sorted(data["substate"].dropna().unique().tolist())
if data["substate"].isna().any():
    available_substates.append("(Missing)")

st.sidebar.header("Dashboard filters")
selected_years = st.sidebar.multiselect(
    "Submission year",
    years,
    default=years,
    help="Includes available reports from partial years; interpret their totals and shares with care.",
)
selected_severities = st.sidebar.multiselect(
    "Severity",
    available_severities,
    default=available_severities,
)
selected_substates = st.sidebar.multiselect(
    "Substate",
    available_substates,
    default=available_substates,
)
render_sidebar_links()

filtered = data[data["report_year"].isin(selected_years)].copy()
if selected_severities and set(selected_severities) != set(available_severities):
    filtered = filtered[filtered["severity"].isin(selected_severities)]
if selected_substates and set(selected_substates) != set(available_substates):
    selected_values = [
        substate for substate in selected_substates if substate != "(Missing)"
    ]
    substate_mask = filtered["substate"].isin(selected_values)
    if "(Missing)" in selected_substates:
        substate_mask |= filtered["substate"].isna()
    filtered = filtered[substate_mask]

typed = filtered[filtered["vuln_type"].notna()].copy()
valid_count = int(filtered["valid_report"].sum())

latest_data_date = data[["submitted_at", "disclosed_at"]].max().max()
if pd.notna(latest_data_date):
    st.caption(f"Data last updated: {latest_data_date:%B %d, %Y}")
if not selected_years:
    st.warning("Select at least one year in the sidebar to display results.")
    st.stop()

metric_columns = st.columns(4)
metric_columns[0].metric("Reports in view", f"{len(filtered):,}")
metric_columns[1].metric("Informative or resolved", f"{valid_count:,}")
metric_columns[2].metric("Programs", f"{filtered['program'].nunique():,}")

overview_tab, trends_tab, ai_tab, bounty_tab, preventability_tab = st.tabs(
    ["Overview", "Trends", "Public AI comparison", "Bounty", "Preventability"]
)

with overview_tab:
    render_overview(filtered, typed)
with trends_tab:
    render_trends(filtered, typed)
with ai_tab:
    render_ai_comparison(data, typed)
with bounty_tab:
    render_bounty(filtered)
with preventability_tab:
    render_preventability()
