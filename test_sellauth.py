import requests

# Replace this with your real API key from SellAuth
SELLAUTH_API_KEY = "5066545|gzx7JN55v214MyXqQWAcoEVxvSix09NZ5CtRuize29f9544f"

headers = {
    "Authorization": f"Bearer {SELLAUTH_API_KEY}",
    "Content-Type": "application/json"
}

url = "https://sellauth.com/api/v1/licenses"

response = requests.get(url, headers=headers)

if response.ok:
    print("✅ API key works! Here's the response:")
    print(response.json())
else:
    print("❌ Failed. Something went wrong.")
    print(f"Status code: {response.status_code}")
    print(response.text)
