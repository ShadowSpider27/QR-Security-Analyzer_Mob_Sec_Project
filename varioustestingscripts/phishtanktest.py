import requests

endpoint = "https://checkurl.phishtank.com/checkurl/"
url = "https://serverbridge.wixstudio.com/enus"

headers = {
    "User-Agent": "phishtank/mobsec-project"
}

response = requests.post(
    endpoint,
    data={
        "url": url,
        "format": "json"
    },
    headers=headers
)

print("\n--- RAW RESPONSE ---")
print(response.text)

