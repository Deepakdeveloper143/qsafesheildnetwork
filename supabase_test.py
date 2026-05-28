import os
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables from .env in project root
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError('Supabase credentials are missing in .env')

# Initialise client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def main():
    try:
        # Simple health check: get current user info using service key
        response = supabase.auth.get_user()
        print('Connection successful. User info:')
        print(response)
    except Exception as e:
        print('Supabase connection failed:', e)

if __name__ == '__main__':
    main()
