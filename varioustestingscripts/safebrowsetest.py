import requests
import json

API_KEY = ""

URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_url(test_url):
    payload = {
        "client": {
            "clientId": "qr-app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": test_url}
            ]
        }
    }

    response = requests.post(URL, json=payload)

    print("\n🔍 Testing URL:", test_url)
    print("Status Code:", response.status_code)

    try:
        data = response.json()

        if "matches" in data:
            print("❌ Result: DANGEROUS")
            print(json.dumps(data, indent=2))
        else:
            print("✅ Result: SAFE (no matches found)")

    except Exception as e:
        print("⚠️ Error parsing response:", str(e))
        print("Raw response:", response.text)


if __name__ == "__main__":
    test_urls = [
        "https://testsafebrowsing.appspot.com/s/phishing.html",
        "https://testsafebrowsing.appspot.com/s/malware.html",
        "https://testsafebrowsing.appspot.com/s/unwanted.html",
        "https://example.com"
    ]

    for url in test_urls:
        check_url(url)