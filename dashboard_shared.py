import pandas as pd
import plotly.graph_objects as go


SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]
SEVERITY_COLORS = {
    "none": "#94a3b8",
    "low": "#42a983",
    "medium": "#e6ae45",
    "high": "#e47755",
    "critical": "#b33b52",
}
PREVENTABILITY_COLORS = {
    1: "#b33b52",
    2: "#e47755",
    3: "#e6ae45",
    4: "#42a983",
    5: "#176b3a",
}
AI_PIVOT = pd.Timestamp("2022-11-30")


def apply_plot_style(fig: go.Figure) -> go.Figure:
    fig.update_layout(
        template="plotly_white",
        margin={"l": 8, "r": 8, "t": 48, "b": 8},
        legend_title_text="",
    )
    return fig