from shodan import Shodan
from time import sleep
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import argparse, requests, json, webbrowser

colorama_init()

parser = argparse.ArgumentParser(description="Hunt for infrastructure using Shodan and URLScan")
parser.add_argument("-q", "--query", type=str, help="Shodan Query")
parser.add_argument("-s", "--shodan", type=str, help="Shodan API Key")
parser.add_argument("-u", "--urlscan", type=str, help="URLScan API Key")

args = parser.parse_args()
shodan_key = args.shodan
shodan_query = args.query
urlscan_key = args.urlscan

def urlscan_submission(url, urlscan_key):
    print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Submitting {url} and showing screenshot in the browser if it has one")
    headers = {"API-Key": urlscan_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    if response.status_code == 429:
        print("{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} We somehow exceeded an API limit. Quitting.")
        quit()
    # Putting the sleep up here because the submission takes some time to run
    print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Sleeping for 20 seconds so URLScan has time to run and I do not exceed quota :)")
    sleep(20)
    uuid = response.json()["uuid"]
    image_url = f"https://urlscan.io/screenshots/{uuid}.png"
    image_request = requests.get(image_url)
    if image_request.status_code == 200:
        print(f"{Fore.GREEN}[RESULT]{Style.RESET_ALL} {url} | {image_url}")
        webbrowser.open(image_url)

def shodan_search(shodan_query, shodan_key, urlscan_key):
    api = Shodan(shodan_key)
    results_to_analyze = set()
    total_results = 0
    for page_number in range(1, 1337):
        print(f"{Fore.LIGHTRED_EX}[SHODAN]{Style.RESET_ALL} Parsing Page: {page_number}")
        results = api.search(query=shodan_query, page=page_number)
        number_of_results = len(results["matches"])
        if number_of_results == 0:
            print(f"{Fore.LIGHTRED_EX}[SHODAN]{Style.RESET_ALL} Results Found: {total_results}")
            break
        elif number_of_results > 0:
            total_results += number_of_results
            for result in results["matches"]:
                ip = str(result["ip_str"])
                port = str(result["port"])
                url = f"http://{ip}:{port}"
                url_tls = f"https://{ip}:{port}"
                results_to_analyze.add(url)
                results_to_analyze.add(url_tls)
    for url in results_to_analyze:
        urlscan_submission(url, urlscan_key)

def main(shodan_query, shodan_key, urlscan_key):
    shodan_search(shodan_query=shodan_query, shodan_key=shodan_key, urlscan_key=urlscan_key)

main(shodan_query, shodan_key, urlscan_key)