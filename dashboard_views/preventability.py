import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard_shared import PREVENTABILITY_COLORS, apply_plot_style
from vuln_classification import PREVENTABILITY_SCALE, owasp_cwe_classification


def render_preventability() -> None:
    preventability_data = pd.DataFrame(
        [
            {
                "Category": category,
                "Score": details.get("preventability"),
                "Rationale": details.get("preventability_rationale", ""),
            }
            for category, details in owasp_cwe_classification.items()
        ]
    )
    scored_categories = preventability_data.dropna(subset=["Score"]).copy()
    if scored_categories.empty:
        st.info("No preventability scores are available.")
    else:
        score_counts = (
            scored_categories["Score"].astype(int)
            .value_counts()
            .reindex(list(PREVENTABILITY_SCALE), fill_value=0)
            .rename_axis("Score")
            .reset_index(name="Categories")
        )
        score_counts["Scale description"] = score_counts["Score"].map(
            PREVENTABILITY_SCALE
        )
        score_counts["Score label"] = score_counts["Score"].astype(str)
        st.subheader("Preventability score distribution")
        chart = px.bar(
            score_counts,
            x="Score",
            y="Categories",
            hover_data={"Scale description": True},
            color="Score label",
            category_orders={
                "Score label": [str(score) for score in PREVENTABILITY_SCALE]
            },
            color_discrete_map={
                str(score): color
                for score, color in PREVENTABILITY_COLORS.items()
            },
        )
        chart.update_xaxes(
            tickvals=list(PREVENTABILITY_SCALE),
            ticktext=["Very hard", "Hard", "Moderate", "Easy", "Very easy"],
            title="Preventability score",
        )
        chart.update_yaxes(title="Number of categories")
        st.plotly_chart(apply_plot_style(chart), width="stretch")

    st.subheader("Preventability scale")
    for score, description in PREVENTABILITY_SCALE.items():
        st.markdown(f"- **{score}/5:** {description}")

    st.subheader("Preventability scores by category")
    table_data = preventability_data.sort_values(
        ["Score", "Category"], na_position="last"
    )

    def color_score(score: float) -> str:
        if pd.isna(score):
            return ""
        return f"color: {PREVENTABILITY_COLORS[int(score)]}; font-weight: bold"

    styled_table = table_data.style.map(color_score, subset=["Score"]).format(
        {"Score": lambda score: f"{int(score)}/5" if pd.notna(score) else "Not scored"}
    )
    st.dataframe(styled_table, width="stretch", height=900, hide_index=True)