import os
import requests
from dotenv import load_dotenv

# Load env variables
load_dotenv()

def test_groq():
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("Error: GROQ_API_KEY not found in environment or .env file.")
        return
    
    print(f"Testing Groq API key: {api_key[:10]}...{api_key[-5:] if len(api_key) > 5 else ''}")
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "llama3-8b-8192",
        "messages": [
            {"role": "user", "content": "Hello! Confirm if this key works by replying with 'Key verified'."}
        ],
        "temperature": 0.2
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            reply = result["choices"][0]["message"]["content"]
            print("\nSuccess! Groq API Response:")
            print(reply)
        else:
            print(f"\nFailed! Groq API returned status code {response.status_code}:")
            print(response.text)
    except Exception as e:
        print(f"\nAn error occurred while making the request: {e}")

if __name__ == "__main__":
    test_groq()
