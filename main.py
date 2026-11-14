import streamlit as st


st.set_page_config(
    page_title="HackerOne Vulnerability Landscape",
    page_icon="🛡️",
    layout="wide",
)

page = st.navigation(
    [
        st.Page(
            "dashboard.py",
            title="Dashboard",
            icon=":material/dashboard:",
            default=True,
        ),
        st.Page(
            "app_pages/methodology.py",
            title="Methodology",
            icon=":material/menu_book:",
        ),
        st.Page(
            "app_pages/publications.py",
            title="Publications",
            icon=":material/article:",
        ),
    ],
    position="hidden",
)
page.run()
