import json
import requests

with open("config.json") as f:
    config = json.load(f)

url = config["base_url"] + config["endpoint"]

response = requests.get(url)

print(f"Status Code: {response.status_code}")
print(response.text)