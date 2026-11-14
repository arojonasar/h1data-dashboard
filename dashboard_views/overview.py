import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard_shared import SEVERITY_COLORS, SEVERITY_ORDER, apply_plot_style
from vuln_classification import owasp_cwe_classification


def render_overview(filtered: pd.DataFrame, typed: pd.DataFrame) -> None:
    with st.container(width=1000):
        st.subheader("Most reported vulnerability types")
        top_n = st.slider("Categories to display", min_value=5, max_value=34, value=20)
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
            st.plotly_chart(apply_plot_style(chart), width="stretch", height=600)
            st.caption(
                "Shares use reports with a known vulnerability type as the denominator "
                f"({len(typed):,} reports)."
            )

    left, right = st.columns([0.4, 0.6])
    with left:
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

    with right:
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