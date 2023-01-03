from shodan import Shodan
from time import sleep
from tqdm import tqdm
import argparse, requests, json, webbrowser

parser = argparse.ArgumentParser(description="Hunt for infrastructure using Shodan and URLScan")
parser.add_argument("-q", "--query", type=str, help="Shodan Query")
parser.add_argument("-s", "--shodan", type=str, help="Shodan API Key")
parser.add_argument("-u", "--urlscan", type=str, help="URLScan API Key")

args = parser.parse_args()
shodan_key = args.shodan
shodan_query = args.query
urlscan_key = args.urlscan

def urlscan_submission(url, urlscan_key):
    # To stay under the anonymous quota but run indefinitely, do not exceed 1 submission per minute
    # The URLscan page says you cannot run more than 2500 in a day
    # 2500 / 1440 (per minute) < 1.7
    # for authenticated, do not exceed 3 per minute
    print("Submitting Result to URLScan and opening URLScan screenshot in browser")
    if urlscan_key != None:
        headers = {"API-Key": urlscan_key, "Content-Type": "application/json"}
        wait = 20
    else:
        headers = {"Content-Type": "application/json"}
        wait = 60
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    print(response)
    # Putting the sleep up here becausse the submission takes some time to run
    print(f"Sleeping {wait} seconds for quota")
    sleep(wait)
    uuid = response.json()["uuid"]
    image_url = f"https://urlscan.io/screenshots/{uuid}.png"
    print(f"{uuid}: {url}")
    webbrowser.open(image_url)

def shodan_search(shodan_query, shodan_key, urlscan_key):
    api = Shodan(shodan_key)
    results_to_analyze = set()
    for page_number in range(1, 2):
        print(f"- Parsing Page {page_number}")
        results = api.search(query=shodan_query, page=page_number)
        number_of_results = len(results["matches"])
        if number_of_results == 0:
            print("- Reached last page\n")
            break
        elif number_of_results > 0:
            for result in results["matches"]:
                ip = str(result["ip_str"])
                port = str(result["port"])
                url = f"http://{ip}:{port}"
                url_tls = f"https://{ip}:{port}"
                results_to_analyze.add(url)
                results_to_analyze.add(url_tls)
    for url in results_to_analyze:
        urlscan_submission(url, urlscan_key)

def urlscan_image_analysis():
    pass

def open_links_in_browser():
    pass

def main(shodan_query, shodan_key, urlscan_key):
    shodan_search(shodan_query=shodan_query, shodan_key=shodan_key, urlscan_key=urlscan_key)

main(shodan_query, shodan_key, urlscan_key)