import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard_shared import SEVERITY_COLORS, SEVERITY_ORDER, apply_plot_style


def render_bounty(filtered: pd.DataFrame) -> None:
    left, right = st.columns([0.6, 0.4])
    with right:
        st.subheader("Bounty reporting status")
        report_count = len(filtered)
        zero_bounty_count = int(filtered["bounty"].eq(0).sum())
        hidden_bounty_count = int(filtered["bounty_hidden"].sum())
        missing_bounty_count = int(filtered["bounty_missing"].sum())
        positive_bounty_count = int(filtered["bounty"].gt(0).sum())
        zero_bounty_share = zero_bounty_count / report_count if report_count else 0
        if report_count:
            bounty_status = pd.DataFrame(
                {
                    "Status": ["$0", "Positive", "Hidden", "Missing"],
                    "Reports": [
                        zero_bounty_count,
                        positive_bounty_count,
                        hidden_bounty_count,
                        missing_bounty_count,
                    ],
                }
            )
            chart = px.pie(
                bounty_status,
                names="Status",
                values="Reports",
                color="Status",
                hole=0.68,
                color_discrete_map={
                    "$0": "#e6ae45",
                    "Positive": "#527c9b",
                    "Hidden": "#94a3b8",
                    "Missing": "#b33b52",
                },
            )
            chart.update_traces(
                textposition="inside",
                textinfo="percent",
                hovertemplate="%{label}: %{value:,.0f} reports (%{percent})<extra></extra>",
            )
            chart.add_annotation(
                x=0.5,
                y=0.5,
                text=f"<b>{zero_bounty_share:.1%}</b><br><sup>report $0</sup>",
                showarrow=False,
            )
            chart.update_layout(height=300, showlegend=True)
            st.plotly_chart(apply_plot_style(chart), width="stretch")
        else:
            st.info("No reports are available for the selected filters.")

    with left:
        st.subheader("Median positive bounty by severity")
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
        st.caption("Median values use disclosed positive bounty amounts only.")