import streamlit as st


def render_sidebar_links() -> None:
    st.sidebar.divider()
    st.sidebar.page_link(
        "dashboard.py", label="Dashboard", icon=":material/dashboard:"
    )
    st.sidebar.page_link(
        "app_pages/methodology.py",
        label="Methodology",
        icon=":material/menu_book:",
    )
    st.sidebar.page_link(
        "app_pages/publications.py",
        label="Publications",
        icon=":material/article:",
    )