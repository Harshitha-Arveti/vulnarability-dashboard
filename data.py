import streamlit as st
import requests

# Function to fetch CVEs from NVD API
def fetch_cves(os_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={os_name}&resultsPerPage=10"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        return data.get("vulnerabilities", [])
    else:
        return None

# Streamlit App
def main():
    st.set_page_config(page_title="OS Vulnerability Dashboard", layout="wide")
    
    # Title
    st.title("📌 OS Vulnerability Dashboard")

    # Buttons at the **top** now
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("🛠️ Test Function"):
            st.success("Test function executed successfully!")
    with col2:
        if st.button("🔍 Identify OS"):
            st.info("OS Identification in progress...")

    # OS-Specific Vulnerability Search
    search_engine()

# Function to create Search Engine
def search_engine():
    st.subheader("🔍 Search OS Vulnerabilities")
    
    os_choice = st.selectbox("Select OS:", ["Android", "iOS", "Windows"])
    
    if os_choice:
        st.subheader(f"Showing latest vulnerabilities for: **{os_choice}**")
        cve_data = fetch_cves(os_choice)
        
        if cve_data:
            for cve in cve_data:
                cve_id = cve["cve"]["id"]
                
                # Extract description, published date, and severity
                description = "No description available"
                if "descriptions" in cve["cve"]:
                    for desc in cve["cve"]["descriptions"]:
                        if desc["lang"] == "en":
                            description = desc["value"]
                            break
                
                published = cve["cve"].get("published", "N/A")
                severity = "N/A"
                if "metrics" in cve["cve"]:
                    if "cvssMetricV2" in cve["cve"]["metrics"]:
                        severity = cve["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"].get("baseSeverity", "N/A")
                
                # Styled CVE Box
                st.markdown(f"""
                    <div style="border: 2px solid #ff5733; border-radius: 10px; padding: 15px; margin-bottom: 10px; 
                                background-color: black; color: white;">
                        <h4>🆔 {cve_id}</h4>
                        <p><b>📝 Description:</b> {description}</p>
                        <p><b>🗓️ Published Date:</b> {published}</p>
                        <p><b>⚠️ Severity:</b> {severity}</p>
                        <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" 
                           style="color: #ffcc00; font-weight: bold;">🔗 More Info</a>
                    </div>
                """, unsafe_allow_html=True)
        else:
            st.warning(f"No vulnerabilities found for {os_choice}.")

# Run the application
if __name__ == "__main__":
    main()
