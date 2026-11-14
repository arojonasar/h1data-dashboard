import pandas as pd
import streamlit as st

from vuln_classification import (
    PREVENTABILITY_SCALE,
    master_map,
    owasp_cwe_classification,
)
from sidebar_navigation import render_sidebar_links


@st.cache_data(show_spinner=False)
def load_vulnerability_types() -> pd.DataFrame:
    return pd.read_csv("data/h1reports.csv", usecols=["vuln_type"])


st.title("Classification & methodology")
render_sidebar_links()
st.markdown(
    """
    HackerOne program owners assign free-text vulnerability labels, which can
    overlap or describe the same underlying weakness in different ways. The
    dashboard applies an explicit, exact-string map to consolidate those labels
    into semantic categories.

    Each category is also associated with CWE references, OWASP Top 10 (2025)
    mappings, root-cause descriptions, and a preventability score.
    """
)

raw_types = load_vulnerability_types()["vuln_type"]
consolidated_types = raw_types.replace(master_map)
detail_labels = set(owasp_cwe_classification)
observed_labels = set(consolidated_types.dropna())
covered_labels = observed_labels & detail_labels
uncovered_labels = sorted(observed_labels - detail_labels)

metrics = st.columns(4)
metrics[0].metric("Raw vulnerability labels", f"{raw_types.nunique(dropna=True):,}")
metrics[1].metric("Labels after exact mapping", f"{consolidated_types.nunique(dropna=True):,}")
metrics[2].metric(
    "Labels with CWE / OWASP details",
    f"{len(covered_labels):,} / {len(observed_labels):,}",
)
metrics[3].metric("Explicit map entries", f"{len(master_map):,}")

if uncovered_labels:
    st.warning(
        f"{len(uncovered_labels)} observed labels have no classification details. "
        "Review the labels below before interpreting category totals."
    )

st.subheader("HackerOne-to-consolidated mapping")
search = st.text_input(
    "Filter by HackerOne label or consolidated label",
    placeholder="For example: Cross-Site Scripting",
)
mapping_table = pd.DataFrame(
    [
        {"HackerOne label": source_label, "Consolidated label": target_label}
        for source_label, target_label in sorted(master_map.items())
    ]
)
if search:
    matches = mapping_table.apply(
        lambda column: column.str.contains(search, case=False, na=False)
    ).any(axis=1)
    mapping_table = mapping_table[matches]
st.dataframe(mapping_table, width="stretch", hide_index=True)

if uncovered_labels:
    with st.expander(f"Observed labels without classification details ({len(uncovered_labels)})"):
        st.write(", ".join(uncovered_labels))

st.subheader("Classification detail")
selected_category = st.selectbox("Choose a classified category", sorted(detail_labels))
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
    st.metric("Preventability", f"{score}/5" if score is not None else "Not scored")
    if score in PREVENTABILITY_SCALE:
        st.write(PREVENTABILITY_SCALE[score])
    rationale = details.get("preventability_rationale")
    if rationale:
        st.markdown("**Rationale**")
        st.write(rationale)

st.subheader("Data preparation and interpretation")
st.markdown(
    """
    - “Valid” reports are those marked `informative` or `resolved` in the source.
      Reports without a vulnerability label are excluded from type-share charts.
    - Yearly type trends use each year's share of typed reports. Available 2014 and
      2026 records are included; 2014 has only 13 reports. The quarterly AI trend
      omits 2014 and the latest incomplete quarter.
    - The severity-over-time chart includes available 2026 data. 2014 has no
      severity values; 2015 has severity for only 14 of 97 reports and is excluded
      by default, with an option to include it.
    - OWASP categories can overlap, so their counts should not be summed as unique
      reports.
    """
)