import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader

def check_authentication():
    """
    Mock authentication using streamlit-authenticator.
    In a real app, this should validate against the FastAPI /login endpoint via JWT.
    """
    # Dummy config for UI mockup purposes
    config_yaml = """
credentials:
  usernames:
    admin:
      email: admin@promptpurify.ai
      name: Admin User
      password: abc # hashed in real life
    analyst:
      email: analyst@promptpurify.ai
      name: Security Analyst
      password: abc
cookie:
  expiry_days: 1
  key: promptpurify_signature_key
  name: promptpurify_auth
preauthorized:
  emails:
  - melsby@gmail.com
"""
    config = yaml.load(config_yaml, Loader=SafeLoader)
    
    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
        config['preauthorized']
    )

    # Note: Streamlit Authenticator V0.3.3 returns name, authentication_status, username
    name, authentication_status, username = authenticator.login('Login', 'main')

    if authentication_status:
        authenticator.logout('Logout', 'sidebar')
        st.sidebar.write(f'Welcome *{name}*')
        return True
    elif authentication_status == False:
        st.error('Username/password is incorrect')
        return False
    elif authentication_status == None:
        st.warning('Please enter your username and password. (Use admin/abc or analyst/abc)')
        return False
