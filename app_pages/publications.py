import streamlit as st

from sidebar_navigation import render_sidebar_links

st.title("Published work")
render_sidebar_links()
st.markdown(
    """
    - Jónasar, A.B., Mallett, J. (2027). [*Vulnerability Patterns in a Decade of Bug Bounty Data*](https://doi.org/10.1007/978-3-032-41330-7_9). In: Alcaraz, C., Conti, M., Katsikas, S., Mouratidis, H. (eds) *Security and Trust Management. STM 2026*. Lecture Notes in Computer Science, vol. 17172. Springer, Cham.
    - Jónasar, A.B. (2026). [*The Usual Suspects: What Bug Bounty Data Reveals About Software Vulnerability*](https://skemman.is/handle/1946/53723). Master's thesis, Reykjavík University.
    """
)