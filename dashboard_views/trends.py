import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard_shared import SEVERITY_COLORS, SEVERITY_ORDER, apply_plot_style


def render_trends(filtered: pd.DataFrame, typed: pd.DataFrame) -> None:
    st.subheader("Reports submitted per year")
    yearly_counts = filtered.groupby("report_year").size().rename("Reports").reset_index()
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
                yearly_types.groupby(["report_year", "vuln_type"])
                .size()
                .rename("Count")
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
        "volumes. 2014 (13 reports) and 2026 are partial, so those points are less stable. "
        "The 2022 marker is a temporal reference only; it does not imply causation."
    )

    st.subheader("Severity mix over time")
    st.caption(
        "Available 2026 reports are included. 2014 has no severity values; 2015 has "
        "severity for only 14 of 97 reports and is excluded by default."
    )
    if st.checkbox("Include low-coverage 2015"):
        severity_by_year = filtered[filtered["severity"].isin(SEVERITY_ORDER)]
    else:
        severity_by_year = filtered[
            filtered["severity"].isin(SEVERITY_ORDER)
            & filtered["report_year"].ne(2015)
        ]
    if severity_by_year.empty:
        st.info("No severity data is available for this selection.")
    else:
        severity_mix = (
            severity_by_year.groupby(["report_year", "severity"])
            .size()
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