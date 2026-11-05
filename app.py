from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from vuln_classification import (
    PREVENTABILITY_SCALE,
    master_map,
    owasp_cwe_classification,
)


st.set_page_config(
    page_title="HackerOne Vulnerability Landscape",
    page_icon="🛡️",
    layout="wide",
)

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
SEVERITY_COLORS = {
    "none": "#94a3b8",
    "low": "#42a983",
    "medium": "#e6ae45",
    "high": "#e47755",
    "critical": "#b33b52",
}
PARTIAL_YEARS = {2014, 2026}
AI_PIVOT = pd.Timestamp("2022-11-30")
REQUIRED_COLUMNS = {
    "program",
    "vuln_type",
    "substate",
    "severity",
    "bounty",
    "submitted_at",
    "disclosed_at",
}

@st.cache_data(show_spinner=False)
def read_csv(contents: bytes) -> pd.DataFrame:
    return pd.read_csv(BytesIO(contents))


def prepare_data(raw: pd.DataFrame) -> pd.DataFrame:
    missing_columns = REQUIRED_COLUMNS.difference(raw.columns)
    if missing_columns:
        raise ValueError(
            "The uploaded data is missing required columns: "
            + ", ".join(sorted(missing_columns))
        )

    df = raw.copy()
    df = df.dropna(subset=["submitted_at"])
    df["raw_vuln_type"] = df["vuln_type"]
    df["submitted_at"] = pd.to_datetime(
        df["submitted_at"], utc=True, errors="coerce"
    ).dt.tz_localize(None)
    df["disclosed_at"] = pd.to_datetime(
        df["disclosed_at"], utc=True, errors="coerce"
    ).dt.tz_localize(None)
    df = df.dropna(subset=["submitted_at"])
    df["report_year"] = df["submitted_at"].dt.year
    df["bounty"] = pd.to_numeric(df["bounty"], errors="coerce")
    df["vuln_type"] = df["vuln_type"].replace(master_map)
    df["valid_report"] = (
        df["substate"].fillna("").str.casefold().isin({"informative", "resolved"})
    )
    df["severity"] = df["severity"].str.casefold()
    return df


def apply_plot_style(fig: go.Figure) -> go.Figure:
    fig.update_layout(
        template="plotly_white",
        margin={"l": 8, "r": 8, "t": 48, "b": 8},
        legend_title_text="",
    )
    return fig


st.title("HackerOne Vulnerability Landscape")
st.caption(
    "An interactive view of publicly disclosed HackerOne reports. "
)

try:
    data = prepare_data(pd.read_csv("data/h1reports.csv"))
except (OSError, pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
    st.error(f"Could not load the report data: {error}")
    st.stop()

years = sorted(data["report_year"].dropna().astype(int).unique().tolist())
complete_years = [year for year in years if year not in PARTIAL_YEARS]
default_years = complete_years or years
available_severities = [
    severity for severity in SEVERITY_ORDER if severity in set(data["severity"].dropna())
]

st.sidebar.header("Dashboard filters")
selected_years = st.sidebar.multiselect(
    "Submission year",
    years,
    default=years,
    #help="2014 and 2026 are partial years in this dataset and are excluded by default.",
)
selected_severities = st.sidebar.multiselect(
    "Severity",
    available_severities,
    default=available_severities,
)
top_n = st.sidebar.slider("Categories in ranking", min_value=5, max_value=25, value=12)

filtered = data[data["report_year"].isin(selected_years)].copy()
if selected_severities and set(selected_severities) != set(available_severities):
    filtered = filtered[filtered["severity"].isin(selected_severities)]
typed = filtered[filtered["vuln_type"].notna()].copy()
valid_count = int(filtered["valid_report"].sum())
# classification_coverage = (
#     typed["vuln_type"].isin(owasp_cwe_classification).mean() * 100
#     if not typed.empty
#     else 0
# )

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
# metric_columns[3].metric(
#     "Observed types with classification details", f"{classification_coverage:.1f}%"
# )

overview_tab, trends_tab, ai_tab, method_tab, publications_tab = st.tabs(
    [
        "Overview",
        "Trends",
        "Public AI comparison",
        "Classification & methodology",
        "Publications",
    ]
)

with overview_tab:
    left, right = st.columns((1.2, 1))

    with left:
        st.subheader("Most-reported vulnerability types")
        if typed.empty:
            st.info("There are no typed reports for the selected filters.")
        else:
            counts = typed["vuln_type"].value_counts().head(top_n).rename_axis(
                "Vulnerability type"
            ).reset_index(name="Reports")
            counts["Share of typed reports"] = counts["Reports"] / len(typed) * 100
            chart = px.bar(
                counts.sort_values("Reports"),
                x="Reports",
                y="Vulnerability type",
                orientation="h",
                hover_data={"Share of typed reports": ":.1f"},
                color_discrete_sequence=["#527c9b"],
            )
            st.plotly_chart(apply_plot_style(chart), width="stretch")
            st.caption(
                f"Shares use reports with a known vulnerability type as the denominator "
                f"({len(typed):,} reports)."
            )

    with right:
        st.subheader("Severity mix")
        severity_data = filtered[filtered["severity"].isin(SEVERITY_ORDER)]
        if severity_data.empty:
            st.info("No severity values are available for the selected filters.")
        else:
            severity_counts = (
                severity_data["severity"]
                .value_counts(normalize=True)
                .reindex(SEVERITY_ORDER, fill_value=0)
                .rename_axis("Severity")
                .reset_index(name="Share")
            )
            severity_counts["Share"] *= 100
            chart = px.bar(
                severity_counts,
                x="Severity",
                y="Share",
                color="Severity",
                category_orders={"Severity": SEVERITY_ORDER},
                color_discrete_map=SEVERITY_COLORS,
                hover_data={"Share": ":.1f"},
            )
            chart.update_layout(yaxis_title="Share of reports (%)")
            st.plotly_chart(apply_plot_style(chart), width="stretch")
            st.caption("Reports without a severity value are not included.")

    bounty_column, owasp_column = st.columns(2)
    with bounty_column:
        st.subheader("Bounty by severity")
        paid = filtered[
            (filtered["bounty"] > 0) & filtered["severity"].isin(SEVERITY_ORDER)
        ]
        if paid.empty:
            st.info("No positive bounty values are available for the selected filters.")
        else:
            bounty_summary = (
                paid.groupby("severity", observed=False)["bounty"]
                .agg(["median", "count"])
                .reindex(SEVERITY_ORDER)
                .dropna(subset=["median"])
                .rename_axis("Severity")
                .reset_index()
            )
            chart = px.bar(
                bounty_summary,
                x="Severity",
                y="median",
                color="Severity",
                category_orders={"Severity": SEVERITY_ORDER},
                color_discrete_map=SEVERITY_COLORS,
                hover_data={"count": True, "median": ":$,.0f"},
            )
            chart.update_layout(yaxis_title="Median positive bounty (USD)")
            st.plotly_chart(apply_plot_style(chart), width="stretch")
            st.caption("Only disclosed positive bounty amounts are included.")

    with owasp_column:
        st.subheader("OWASP Top 10 (2025)")
        owasp_data = typed[typed["vuln_type"].isin(owasp_cwe_classification)].copy()
        if owasp_data.empty:
            st.info("No observed categories have OWASP details for the selected filters.")
        else:
            owasp_data["OWASP category"] = owasp_data["vuln_type"].map(
                lambda category: owasp_cwe_classification[category]["owasp_2025"]
            )
            owasp_counts = (
                owasp_data.explode("OWASP category")["OWASP category"]
                .value_counts()
                .rename_axis("OWASP category")
                .reset_index(name="Reports")
                .sort_values("Reports")
            )
            chart = px.bar(
                owasp_counts,
                x="Reports",
                y="OWASP category",
                orientation="h",
                color_discrete_sequence=["#9274aa"],
            )
            st.plotly_chart(apply_plot_style(chart), width="stretch")
            st.caption(
                "A vulnerability type can map to multiple OWASP categories, so "
                "these counts overlap."
            )

with trends_tab:
    st.subheader("Reports submitted per year")
    yearly_counts = (
        filtered.groupby("report_year").size().rename("Reports").reset_index()
    )
    chart = px.bar(
        yearly_counts,
        x="report_year",
        y="Reports",
        color_discrete_sequence=["#527c9b"],
    )
    chart.update_xaxes(dtick=1, title="Submission year")
    st.plotly_chart(apply_plot_style(chart), width="stretch")

    st.subheader("Vulnerability mix over time")
    if typed.empty:
        st.info("There are no typed reports for the selected filters.")
    else:
        top_types = typed["vuln_type"].value_counts().head(8).index.tolist()
        chosen_types = st.multiselect(
            "Types to compare",
            options=sorted(typed["vuln_type"].unique()),
            default=top_types,
        )
        if chosen_types:
            yearly_types = typed[typed["vuln_type"].isin(chosen_types)]
            yearly_mix = (
                yearly_types.groupby(["report_year", "vuln_type"]).size().rename("Count")
                .reset_index()
            )
            yearly_totals = typed.groupby("report_year").size().rename("Year total")
            yearly_mix = yearly_mix.join(yearly_totals, on="report_year")
            yearly_mix["Share"] = yearly_mix["Count"] / yearly_mix["Year total"] * 100
            chart = px.line(
                yearly_mix,
                x="report_year",
                y="Share",
                color="vuln_type",
                markers=True,
                hover_data={"Count": True, "Year total": True, "Share": ":.1f"},
            )
            chart.update_xaxes(dtick=1, title="Submission year")
            chart.update_yaxes(title="Share of typed reports (%)")
            chart.add_vline(
                x=2022.8,
                line_dash="dash",
                line_color="#94a3b8",
                annotation_text="ChatGPT launch (Nov 2022)",
                annotation_position="top",
            )
            st.plotly_chart(apply_plot_style(chart), width="stretch")
        else:
            st.info("Choose at least one vulnerability type to display the trend.")
    st.caption(
        "Yearly comparisons use within-year shares to account for varying report "
        "volumes. The 2022 marker is a temporal reference only; it does not imply causation."
    )

    st.subheader("Severity mix over time")
    
    st.caption(
        "2014, 2015, and 2026 are excluded from this severity comparison; "
        "2015 has substantial missing severity."
    )

    if st.checkbox("Include partial years"):
        sev_all = data[data["report_year"].isin(years)]
        severity_by_year = sev_all[
            sev_all["severity"].isin(SEVERITY_ORDER)
        ]
    else:
        severity_by_year = filtered[
            filtered["severity"].isin(SEVERITY_ORDER)
            & ~filtered["report_year"].isin({2014, 2015, 2026})
    ]
    if severity_by_year.empty:
        st.info("No complete-year severity data is available for this selection.")
    else:
        severity_mix = (
            severity_by_year.groupby(["report_year", "severity"]).size()
            .rename("Reports")
            .reset_index()
        )
        totals = severity_by_year.groupby("report_year").size().rename("Year total")
        severity_mix = severity_mix.join(totals, on="report_year")
        severity_mix["Share"] = severity_mix["Reports"] / severity_mix["Year total"] * 100
        chart = px.area(
            severity_mix,
            x="report_year",
            y="Share",
            color="severity",
            category_orders={"severity": SEVERITY_ORDER},
            color_discrete_map=SEVERITY_COLORS,
            hover_data={"Reports": True, "Share": ":.1f"},
        )
        chart.update_xaxes(dtick=1, title="Submission year")
        chart.update_yaxes(title="Share of reports with severity (%)")
        st.plotly_chart(apply_plot_style(chart), width="stretch")

with ai_tab:
    st.subheader("Vulnerability mix before and after public generative AI")
    st.caption(
        "The public launch of ChatGPT on 30 November 2022 is used as a time marker. "
        "This descriptive comparison does not imply that AI caused any observed change."
    )
    eras = typed[
        # ~typed["report_year"].isin(PARTIAL_YEARS)
        # & 
        typed["submitted_at"].notna()
    ].copy()
    if eras.empty:
        st.info("There are not enough full-year typed reports for this comparison.")
    else:
        eras["Period"] = eras["submitted_at"].lt(AI_PIVOT).map(
            {True: "Before", False: "After"}
        )
        all_types = sorted(eras["vuln_type"].unique())
        chosen_types = st.multiselect(
            "Vulnerability types",
            options=all_types,
            default=all_types,
            help="All consolidated types are selected by default.",
        )
        if not chosen_types:
            st.info("Choose at least one vulnerability type to display the comparison.")
        else:
            counts = (
                eras.groupby(["vuln_type", "Period"], observed=False)
                .size()
                .rename("Reports")
            )
            type_period_index = pd.MultiIndex.from_product(
                [chosen_types, ["Before", "After"]],
                names=["vuln_type", "Period"],
            )
            shares = counts.reindex(type_period_index, fill_value=0).reset_index()
            period_totals = eras.groupby("Period", observed=False).size().rename(
                "Period total"
            )
            shares = shares.join(period_totals, on="Period")
            shares["Share (%)"] = shares["Reports"] / shares["Period total"] * 100
            type_order = (
                shares.groupby("vuln_type")["Share (%)"]
                .mean()
                .sort_values(ascending=False)
                .index.tolist()
            )
            chart = px.bar(
                shares,
                x="Share (%)",
                y="vuln_type",
                color="Period",
                barmode="group",
                orientation="h",
                category_orders={
                    "Period": ["After", "Before"],
                    "vuln_type": type_order,
                },
                color_discrete_map={"After": "#e47755", "Before": "#527c9b"},
                hover_data={"Reports": True, "Period total": True, "Share (%)": ":.2f"},
            )
            chart.update_layout(
                xaxis_title="Share of typed reports in period (%)",
                yaxis_title="",
                legend_traceorder="reversed",
                height=max(500, len(chosen_types) * 27 + 120),
            )
            st.plotly_chart(apply_plot_style(chart), width="stretch")

with method_tab:
    st.subheader("How vulnerability types were consolidated")
    st.markdown(
        """
        The HackerOne platform allows program owners to assign a free-text label to
        each report's vulnerability type. This results in many overlapping and
        inconsistent labels for the same underlying vulnerability category. For
        example, the same underlying vulnerability may be labeled as `XSS`, `XSS - Reflected`,
        `Cross-Site Scripting`, or `Cross Site Scripting (XSS)`.
        To make this data more useful for analysis, the raw labels are mapped to a smaller set of
        semantic categories that are more consistent and meaningful. The mapping is based on the 
        author's review of the raw labels and their understanding of common vulnerability types. 
        
        The resulting semantic categories are then annotated with additional information, 
        such as CWE identifiers, OWASP Top 10 categories, root causes, and preventability scores.
        """
    )

    raw_type_count = int(data["raw_vuln_type"].nunique(dropna=True))
    consolidated_type_count = int(data["vuln_type"].nunique(dropna=True))
    detail_labels = set(owasp_cwe_classification)
    observed_labels = set(data["vuln_type"].dropna())
    covered_labels = observed_labels & detail_labels
    uncovered_labels = sorted(observed_labels - detail_labels)

    method_metrics = st.columns(4)
    method_metrics[0].metric("Raw vulnerability labels", f"{raw_type_count:,}")
    method_metrics[1].metric(
        "Labels after exact mapping", f"{consolidated_type_count:,}"
    )
    method_metrics[2].metric(
        "Labels with CWE / OWASP details", f"{len(covered_labels):,} / {len(observed_labels):,}"
    )
    method_metrics[3].metric("Explicit map entries", f"{len(master_map):,}")

    if consolidated_type_count != len(detail_labels) or uncovered_labels:
        st.warning(
            f"The current mapping produces {consolidated_type_count} observed "
            f"labels, with {len(uncovered_labels)} lacking classification details. "
            "Review new or unmapped labels in the table below and update their "
            "classification before interpreting category totals."
        )
    st.caption(
        "Detailed CWE, OWASP Top 10 (2025), "
        f"root-cause, and preventability metadata for {len(detail_labels)} semantic "
        f"categories. {len(uncovered_labels)} observed labels currently have no "
        "matching detail record."
    )

    st.markdown("#### Search the HackerOne-to-consolidated mapping")
    search = st.text_input(
        "Filter by HackerOne label or consolidated label",
        placeholder="For example: Cross-Site Scripting",
    )
    mapping_rows = [
        {
            "HackerOne label": source_label,
            "Consolidated label": target_label,
        }
        for source_label, target_label in sorted(master_map.items())
    ]
    mapping_table = pd.DataFrame(mapping_rows)
    if search:
        matches = mapping_table.apply(
            lambda column: column.str.contains(search, case=False, na=False)
        ).any(axis=1)
        mapping_table = mapping_table[matches]
    st.dataframe(mapping_table, width="stretch", hide_index=True)

    if uncovered_labels:
        with st.expander(f"Observed labels without classification details ({len(uncovered_labels)})"):
            st.write(", ".join(uncovered_labels))
    
    st.markdown("#### Classification detail")
    if detail_labels:
        detail_options = sorted(detail_labels)
        selected_category = st.selectbox("Choose a classified category", detail_options)
        details = owasp_cwe_classification[selected_category]
        left, right = st.columns(2)
        with left:
            st.markdown("**OWASP Top 10 (2025)**")
            for category in details.get("owasp_2025", []):
                st.write(f"- {category}")
            st.markdown("**CWE references**")
            st.write(", ".join(details.get("cwes", [])) or "Not specified")
            st.markdown("**Root-cause descriptions**")
            for cause in details.get("root_causes", []):
                st.write(f"- {cause}")
        with right:
            score = details.get("preventability")
            st.metric(
                "Preventability",
                f"{score}/5" if score is not None else "Not scored",
            )
            if score in PREVENTABILITY_SCALE:
                st.write(PREVENTABILITY_SCALE[score])
            rationale = details.get("preventability_rationale")
            if rationale:
                st.markdown("**Rationale**")
                st.write(rationale)

    st.markdown("#### Data preparation and interpretation")
    st.markdown(
        """
        - Rows without a submission timestamp are removed; timestamps are parsed as
          UTC and grouped by submission year.
        - “Valid” reports are those marked `informative` or `resolved` in the source.
          Reports with missing vulnerability labels are excluded from type-share charts.
        - Yearly type trends use each year's share of typed reports, not raw counts.
          2014 and 2026 are partial years and are omitted by default; 2015 is also
          omitted from yearly severity comparisons because severity data is
          substantially incomplete.
        - OWASP categories can be multiple per vulnerability type, so category report
          totals may overlap and should not be summed as unique reports.
        """
    )


with publications_tab:
    st.subheader("Published work")
    st.markdown(
        """
        - Jónasar, A.B. (2026). [*The Usual Suspects: What Bug Bounty Data Reveals About Software Vulnerability*](https://skemman.is/handle/1946/53723). Master's thesis, Reykjavík University.
        - Jónasar, A.B., Mallett, J. (2027). [*Vulnerability Patterns in a Decade of Bug Bounty Data*](https://doi.org/10.1007/978-3-032-41330-7_9). In: Alcaraz, C., Conti, M., Katsikas, S., Mouratidis, H. (eds) *Security and Trust Management. STM 2026*. Lecture Notes in Computer Science, vol. 17172. Springer, Cham.
        """
    )
