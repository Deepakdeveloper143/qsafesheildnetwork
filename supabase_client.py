'''supabase_client.py

"""Utility module for connecting to Supabase.

This module provides a singleton ``supabase`` client instance that can be imported
by other parts of the Risk Analyzer project.

Prerequisites
-------------
* ``supabase`` Python client library (`pip install supabase`)
* ``python-dotenv`` for loading environment variables (`pip install python-dotenv`)
* In the project's ``.env`` file define:
    * ``SUPABASE_URL`` – the Supabase project URL.
    * ``SUPABASE_KEY`` – the service role key (or anon key if only public data).

Example usage
-------------
>>> from supabase_client import supabase
>>> data = supabase.table('risk_assessments').select('*').execute()
>>> print(data.data)
"""

import os
from pathlib import Path
from supabase import create_client, Client
from dotenv import load_dotenv

# Load .env from the project root (the same directory as this file)
project_root = Path(__file__).resolve().parent
env_path = project_root / ".env"
load_dotenv(dotenv_path=env_path)

# Retrieve credentials – raise a clear error if missing
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "Supabase credentials not found. Please set SUPABASE_URL and SUPABASE_KEY in the .env file."
    )

# Create a singleton client – reuse across imports
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

__all__ = ["supabase"]
'''
