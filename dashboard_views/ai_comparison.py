import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard_shared import AI_PIVOT, apply_plot_style


def render_ai_comparison(data: pd.DataFrame, typed: pd.DataFrame) -> None:
    st.subheader("Vulnerability mix before and after public generative AI")
    st.caption("The public launch of ChatGPT on 30 November 2022 is used as a time marker.")
    eras = typed[typed["submitted_at"].notna()].copy()
    if eras.empty:
        st.info("There are no typed reports for these filters.")
        return

    eras["Period"] = eras["submitted_at"].lt(AI_PIVOT).map(
        {True: "Before", False: "After"}
    )
    all_types = sorted(eras["vuln_type"].unique())
    top_types = eras["vuln_type"].value_counts().index.tolist()
    chosen_types = st.multiselect(
        "Vulnerability types",
        options=all_types,
        default=top_types,
    )
    if not chosen_types:
        st.info("Choose at least one vulnerability type to display the comparison.")
        return

    counts = eras.groupby(["vuln_type", "Period"], observed=False).size().rename("Reports")
    type_period_index = pd.MultiIndex.from_product(
        [chosen_types, ["Before", "After"]],
        names=["vuln_type", "Period"],
    )
    shares = counts.reindex(type_period_index, fill_value=0).reset_index()
    period_totals = eras.groupby("Period", observed=False).size().rename("Period total")
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

    st.subheader("Quarterly vulnerability trends")
    quarterly_eras = eras[eras["report_year"].ne(2014)].copy()
    if not quarterly_eras.empty:
        quarterly_eras["Quarter"] = (
            quarterly_eras["submitted_at"].dt.to_period("Q").dt.start_time
        )
        latest_submission = data["submitted_at"].max()
        latest_quarter = latest_submission.to_period("Q").start_time
        latest_quarter_end = latest_quarter + pd.offsets.QuarterEnd()
        if latest_submission < latest_quarter_end:
            quarterly_eras = quarterly_eras[
                quarterly_eras["Quarter"].ne(latest_quarter)
            ]

    if quarterly_eras.empty:
        st.info("No complete quarters are available for the time series.")
        return

    st.info(
        "Double-click a legend item to isolate that vulnerability type; "
        "double-click again to show all types.",
        icon=":material/tips_and_updates:",
    )
    quarterly_type_counts = (
        quarterly_eras[quarterly_eras["vuln_type"].isin(chosen_types)]
        .groupby(["Quarter", "vuln_type"])
        .size()
        .rename("Reports")
        .reset_index()
    )
    quarterly_totals = quarterly_eras.groupby("Quarter").size().rename("Quarter total")
    quarters = pd.date_range(
        quarterly_eras["Quarter"].min(),
        quarterly_eras["Quarter"].max(),
        freq="QS",
    )
    quarter_type_index = pd.MultiIndex.from_product(
        [quarters, chosen_types],
        names=["Quarter", "vuln_type"],
    )
    quarterly_mix = (
        quarterly_type_counts.set_index(["Quarter", "vuln_type"])
        .reindex(quarter_type_index, fill_value=0)
        .reset_index()
        .join(quarterly_totals, on="Quarter")
    )
    quarterly_mix["Share (%)"] = (
        quarterly_mix["Reports"] / quarterly_mix["Quarter total"] * 100
    )
    chart = px.line(
        quarterly_mix,
        x="Quarter",
        y="Share (%)",
        color="vuln_type",
        hover_data={"Reports": True, "Quarter total": True, "Share (%)": ":.2f"},
    )
    chart.add_vline(
        x=AI_PIVOT,
        line_dash="dash",
        line_color="#94a3b8",
        annotation_text="ChatGPT launch (30 Nov 2022)",
        annotation_position="top",
    )
    chart.update_xaxes(title="Quarter")
    chart.update_yaxes(title="Share of typed reports (%)")
    chart.update_layout(height=520)
    st.plotly_chart(apply_plot_style(chart), width="stretch")
    st.caption(
        "2014 is omitted because it contains only 13 reports. 2026 is included "
        "through its latest complete quarter; the incomplete quarter is omitted. "
        "Q4 2022 includes reports from both before and after the launch date."
    )