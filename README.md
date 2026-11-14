# HackerOne Vulnerability Landscape Dashboard

An interactive Streamlit dashboard for public HackerOne reports. It includes
vulnerability rankings, severity and bounty summaries, yearly trends, a
pre-/post-public-generative-AI comparison, and a searchable classification
lookup.

## Run locally

From this directory:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run main.py
```

The dashboard currently reads report data from `data/h1reports.csv`. The file
should contain `program`, `vuln_type`, `substate`, `severity`, `bounty`,
`submitted_at`, and `disclosed_at` columns.

## Code layout

- `main.py` registers the Dashboard, Methodology, and Publications pages.
- `dashboard.py` loads and filters the data, shows summary metrics, and arranges
	the horizontal analysis tabs.
- `dashboard_views/` contains one renderer per analysis tab: Overview, Trends,
	Public AI comparison, Bounty, and Preventability.
- `dashboard_shared.py` contains shared chart colors, dates, and styling.

## Vulnerability classification

`vuln_classification.py` defines the label mappings and category metadata used
by the dashboard:

- `master_map` consolidates source vulnerability labels into semantic
	categories using exact-string matches. Labels not listed in the map are kept
	unchanged; the app does not use fuzzy matching or infer labels from report
	text.
- `owasp_cwe_classification` provides category details, including CWE
	references, OWASP Top 10 (2025) categories, root-cause descriptions, and
	preventability scores with rationales. The dashboard uses these details in
	the OWASP summary and the Methodology page in the sidebar.
- `PREVENTABILITY_SCALE` explains the qualitative 1–5 scores, from very hard
	to very easy to prevent.

