import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from os_ident import get_os_identifier
import random
from vulnerability import vulnerabilities
from dotenv import load_dotenv
from pymongo import MongoClient
import os
import bcrypt
import requests

# Load environment variables
load_dotenv()
client = MongoClient(os.getenv("MONGO_CLIENT"))
db = client["PCL"]
users_collection = db["Users"]
vulnerabilities_collection = db["Vulnerabilities"]

def get_vulnerabilities_from_db(platform, version=None):
    query = {"platform": platform}
    if version:
        query["version"] = version
    return list(vulnerabilities_collection.find(query))

def fetch_latest_news():
    news_api_url = "https://newsapi.org/v2/top-headlines"
    params = {
        "category": "technology",
        "q": "cybersecurity",
        "apiKey": os.getenv("NEWS_API_KEY")
    }
    try:
        response = requests.get(news_api_url, params=params)
        if response.status_code == 200:
            return response.json().get("articles", [])
        else:
            return [{"title": "Error fetching news", "description": f"API responded with status {response.status_code}"}]
    except Exception as e:
        return [{"title": "Error fetching news", "description": str(e)}]

def visualize_vulnerabilities():
    if st.session_state.get("login", False):
        st.title('Visualize Vulnerabilities')
        platform = st.selectbox("Select Platform", ['Android', 'iOS', 'Windows'])
        
        data = get_vulnerabilities_from_db(platform)
        
        if not data:
            st.warning(f"No data found for {platform}. Please check database entries.")
            return
        
        df = pd.DataFrame(data)
        if df.empty or 'year' not in df.columns:
            st.warning("No valid year data available for visualization.")
            return
        
        df['year'] = pd.to_numeric(df['year'], errors='coerce')
        df = df.dropna(subset=['year'])
        df_grouped = df.groupby('year').size().reset_index(name='Count')

        if df_grouped.empty:
            st.warning("No valid data available for visualization.")
            return

        fig, ax = plt.subplots()
        ax.plot(df_grouped['year'], df_grouped['Count'], color='lime', marker='o', linestyle='-', linewidth=2)
        ax.set_facecolor('black')
        fig.patch.set_facecolor('black')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.xaxis.label.set_color('white')
        ax.yaxis.label.set_color('white')
        ax.title.set_color('white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
        ax.set_xlabel('Year')
        ax.set_ylabel('Number of Vulnerabilities')
        ax.set_title(f'Vulnerabilities in {platform}')
        st.pyplot(fig)
    else:
        st.error("Please sign in to access the visualization feature.")

def home_page():
    st.title("Vulnerability Identification Dashboard")
    st.write("This dashboard provides real-time insights into vulnerabilities across Android, iOS, and Windows platforms. Users can explore security risks, track latest updates, and engage with cybersecurity news.")

def dashboard_page():
    st.title('Vulnerability Dashboard')
    st.write("Select a platform and version to explore known vulnerabilities.")
    platform = st.selectbox("Select Platform", ['Android', 'iOS', 'Windows'])
    version = st.selectbox("Select Version", list(vulnerabilities.get(platform, {}).keys()))
    vuln_data = get_vulnerabilities_from_db(platform, version)
    
    if not vuln_data:
        st.warning("No vulnerabilities found for the selected platform and version.")
    else:
        df = pd.DataFrame(vuln_data)
        st.write("### Vulnerabilities Table")
        st.dataframe(df[['CVE_ID', 'description', 'year']])
    
    if st.button("Identify OS"):
        os_identified = get_os_identifier()
        st.write(f"Identified OS: {os_identified}")

def sign_in_page():
    st.title("Sign In")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Sign In"):
        user = users_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            st.session_state.login = True
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")

def sign_up_page():
    st.title("Sign Up")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")
    if st.button("Sign Up"):
        if users_collection.find_one({"username": username}):
            st.error("Username already taken. Please choose another.")
        else:
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            users_collection.insert_one({"username": username, "password": hashed_pw})
            st.success("Account created successfully! Please sign in.")

st.sidebar.title('Navigation')
section = st.sidebar.selectbox("Select a Section", ['🏠 Home', '📊 Dashboard', '📈 Visualize', '🔑 Sign In', '🆕 Sign Up', '📢 Latest Updates', '📰 News'])

if section == '🏠 Home':
    home_page()
elif section == '📊 Dashboard':
    dashboard_page()
elif section == '📈 Visualize':
    visualize_vulnerabilities()
elif section == '🔑 Sign In':
    sign_in_page()
elif section == '🆕 Sign Up':
    sign_up_page()