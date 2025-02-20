import streamlit as st
import pandas as pd
from os_ident import get_os_identifier
import random
from vulnerability import vulnerabilities
import pandas as pd
from pymongo import MongoClient
import os
import bcrypt
import requests

client = MongoClient(os.getenv("MONGO_CLIENT"))
db = client["PCL"]
users_collection = db["Users"]

def get_data(username, item):
    data = users_collection.distinct(item, {"username": username})

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Helper function to verify password
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password)

def login_user(username, password):
    user = users_collection.find_one({"username": username})
    if user and verify_password(user["password"], password):
        return True
    return False

def signup(username, password, name, email):
    if users_collection.find_one({"username": username}):
        return False
    
    hashed_password = hash_password(password)
    users_collection.insert_one({
        "username": username,
        "password": hashed_password,
        "name": name,
        "email": email
    })
    return True

if 'login' not in st.session_state:
    st.session_state.login = False

# Simulate some latest updates and news
latest_updates = [
    {"title": "Android 14 Security Patch", "update": "Android 14 just received a critical security patch fixing vulnerabilities in system services."},
    {"title": "iOS 17 Vulnerability", "update": "iOS 17 fixes a security hole that allowed unauthorized access to system services."},
    {"title": "Windows 11 Update", "update": "Windows 11 rolls out an emergency patch to fix SMBv3 remote code execution vulnerabilities."},
]

latest_news = [
    {"title": "Cybersecurity Threats Rising in 2025", "summary": "Cybersecurity threats are on the rise in 2025, with new forms of attacks like AI-based malware."},
    {"title": "Zero-Day Exploit in Android", "summary": "A new zero-day exploit in Android has been discovered, allowing attackers to bypass security."},
    {"title": "Windows OS Faces New Ransomware Attack", "summary": "A ransomware attack on Windows OS has been reported, causing data breaches in several organizations."},
]


st.set_page_config(page_title="Vulnerability Dashboard", page_icon=":shield:", layout="wide")

# Function to visualize vulnerability counts
def visualize_vulnerabilities():
    if st.session_state.login:
        st.title('Visualize Vulnerabilities')
        st.write("This section allows you to visualize the number of vulnerabilities in different platforms.")
        
        platform = st.selectbox("Select Platform", ['Android', 'iOS', 'Windows'])

        if platform == 'Android':
            st.image("android.png")
        elif platform == 'iOS':
            st.image("ios.png")
        elif platform == 'Windows':
            st.image("windows.png")


    else:
        st.error("Please sign in to access the visualization feature.")
# Function to display solutions

# Function to create the Home page layout
def home_page():
    st.title('Vulnerability Dashboard')
    st.write("Welcome to the vulnerability dashboard! Here, you can find details about vulnerabilities in different platforms (Android, iOS, Windows) and their specific versions.")
    
    # Title section (can be expanded with more info about the dashboard if needed)
    st.subheader("Overview")
    st.write("This dashboard provides details about vulnerabilities in various platforms (Android, iOS, and Windows).")
    
    # Latest Updates Section (within the Home Page content)
    st.header("Latest Updates")
    for update in latest_updates:
        st.subheader(update["title"])
        st.write(update["update"])
        st.write("---")

    # Latest News Section (within the Home Page content)
    st.header("Latest News")
    for news in latest_news:
        st.subheader(news["title"])
        st.write(news["summary"])
        st.write("---")

# Function to display Dashboard
def dashboard_page():
    if st.session_state.login:
        st.title('Vulnerability Dashboard')
        
        platform = st.selectbox("Select Platform", ['Android', 'iOS', 'Windows'])
        version = st.selectbox("Select Version", list(vulnerabilities[platform].keys()))
        
        st.subheader(f"Vulnerabilities in {platform} {version}")
        for vuln in vulnerabilities[platform][version]:
            st.write(vuln)
    else:
        st.error("Please sign in to access the Dashboard feature.")
    

# Function to create a Search Engine
def search_engine():
    if st.session_state.login:
        st.title('Search Vulnerabilities')
        search_query = st.text_input('Enter vulnerability name or keyword:')
        
        sheet_id = "123PV6s6z0NcmpA8HDkn0fvbWhpEW10zOBn49y_lRN5o"
        sheet_name = "Vulnerabilities"
        url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={sheet_name}"
        df = pd.read_csv(url, dtype=str)

        m1 = df['CVE Number'].str.contains(search_query, case=False)
        m2 = df['Description'].str.contains(search_query, case=False)
        m3 = df['OS'].str.contains(search_query, case=False)
        m4 = df['Version'].str.contains(search_query, case=False)
        m5 = df['Year'].str.contains(search_query, case=False)
        df_filtered = df[m1 | m2 | m3 | m4 | m5]
        cards = 3
        if search_query:
            for n_row, row in df_filtered.reset_index().iterrows():
                i = n_row % cards
                if i == 0:
                    st.write('---')
                    cols = st.columns(cards, gap='large')
                with cols[n_row % cards]:
                    st.write(row['CVE Number'])
                    st.write(row['Description'])
                    st.write(row['OS'])
                    st.write(row['Version'])
                    st.write(row['Year'])
                    st.write('---')
    else:
        st.error("Please sign in to access the search Engine feature.")

# Function to create Sign-Up and Sign-In (basic mock)
def auth_page():
    st.title('Sign In / Sign Up')
    
    choice = st.radio("Choose an option", ['Sign In', 'Sign Up'])
    
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    
    if choice == 'Sign Up':
        name = st.text_input("Full Name")
        email = st.text_input("Email")

        if st.button('Sign Up'):
            if signup(username, password, name, email):
                st.success(f"Welcome, {name}! You've successfully signed up.")
            else:
                st.error("Username already exists. Please sign in.")
    else:
        if st.button('Sign In'):
            if login_user(username, password):
                st.session_state.login = True
                st.success(f"Welcome back, {username}!")
            else:
                st.error("Invalid username or password. Please try again.")

# Function to display Live Chat (mock chat)
def live_chat():
    if st.session_state.login:
        st.title('Live Chat Support')
        st.write("Chat with our support team below.")
        
        message = st.text_input("Your Message")
        if st.button("Send"):
            st.write(f"Sent: {message}")
        st.write("Response: Thank you for reaching out!")
    else:
        st.error("Please sign in to access the live chat.")

# Sidebar for Navigation with dropdowns and symbols
# Title for Sidebar
st.sidebar.title('Navigation')

# Create the sidebar with dropdowns for each section with symbols
section = st.sidebar.selectbox("Select a Section", [
    '🏠 Home', 
    '📊 Dashboard', 
    '🔍 Search Engine', 
    '🔒 Sign In / Sign Up', 
    '💬 Live Chat',
    '📈 Visualize'
])

with st.sidebar:
    if st.button("Logout"):
        st.session_state.login = False

if section == '🏠 Home':
    home_dropdown = st.sidebar.selectbox("Select Option", ['Title & Main Concept', 'Latest Updates', 'Latest News'])
    if home_dropdown == 'Title & Main Concept':
        st.subheader("Welcome to the Dashboard for identifing vulnerabilities")
        st.write("""
            This platform helps you stay updated with the latest vulnerabilities across various platforms including 
            Android, iOS, and Windows. The dashboard provides an overview of vulnerabilities based on platform versions,
            making it easier for users to track security issues and apply necessary patches. You can also explore recent updates
            and news related to security threats to stay informed.
        """)
    elif home_dropdown == 'Latest Updates':
        st.subheader("Latest Updates")
        for update in latest_updates:
            st.subheader(update["title"])
            st.write(update["update"])
            st.write("---")
    elif home_dropdown == 'Latest News':
        st.subheader("Latest News")
        for news in latest_news:
            st.subheader(news["title"])
            st.write(news["summary"])
            st.write("---")


elif section == '📊 Dashboard':
    if st.session_state.login:
        dashboard_dropdown = st.sidebar.selectbox("Select Platform", ['Android', 'iOS', 'Windows'])
        if dashboard_dropdown == 'Android':
            st.subheader("Android Vulnerabilities")
            platform = 'Android'
            version = st.selectbox("Select Version", list(vulnerabilities[platform].keys()))
            
            st.subheader("Test")
            if st.button("Test"):
                choice = vulnerabilities['Android']['Version 14'][20]
                st.write(choice)
    
            st.subheader("Identify OS")
            if st.button("Identify OS"):
                identify = get_os_identifier()
                st.write(identify)
            
            for vuln in vulnerabilities[platform][version]:
                st.table(vuln)
    
        elif dashboard_dropdown == 'iOS':
            st.subheader("iOS Vulnerabilities")
            platform = 'iOS'
            version = st.selectbox("Select Version", list(vulnerabilities[platform].keys()))
    
            st.subheader("Test")
            if st.button("Test"):
                st.write("This is not an IOS Device")
    
            st.subheader("Identify OS")
            if st.button("Identify OS"):
                identify = get_os_identifier()
                st.write(identify)
    
            for vuln in vulnerabilities[platform][version]:
                st.table(vuln)
    
        
    
        elif dashboard_dropdown == 'Windows':
            st.subheader("Windows Vulnerabilities")
            platform = 'Windows'
            version = st.selectbox("Select Version", list(vulnerabilities[platform].keys()))
            
            st.subheader("Test")
            if st.button("Test"):
                st.write("This is not a Windows device")
    
            st.subheader("Identify OS")
            if st.button("Identify OS"):
                identify = get_os_identifier()
                st.write(identify)
    
            for vuln in vulnerabilities[platform][version]:
                st.table(vuln)
    else:
        st.error("Please sign in to access the Dashboard feature.")
        
    
    


elif section == '🔍 Search Engine':
    search_engine()

elif section == '🔒 Sign In / Sign Up':
    auth_page()

elif section == '💬 Live Chat':
    live_chat()
elif section == '📈 Visualize':
    visualize_vulnerabilities()
# Separate dropdown for Solutions and Testing

