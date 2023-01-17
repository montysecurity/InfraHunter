from shodan import Shodan
from time import sleep
from tqdm import tqdm
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import argparse, requests, json, webbrowser, hashlib, os

colorama_init()

parser = argparse.ArgumentParser(description="Hunt for infrastructure using Shodan and URLScan")
parser.add_argument("-q", "--query", type=str, help="Shodan Query")
parser.add_argument("-s", "--shodan", type=str, help="Shodan API Key")
parser.add_argument("-u", "--urlscan", type=str, help="URLScan API Key")
parser.add_argument("--scan-type", type=str, default="public", help="URL Scan Type (default: Public")
parser.add_argument("--no-browser", action="store_true", help="Do not open a browser")

args = parser.parse_args()
shodan_key = args.shodan
shodan_query = args.query
urlscan_key = args.urlscan
no_browser = args.no_browser
scan_type = args.scan_type

uuids = {}

def open_links(uuids):
    current_links = []
    count_of_uuids = len(uuids)
    results = 0
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Analysing {count_of_uuids} URLs")
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} This may take a while since I have to do a lot of hashing")
    for uuid in uuids:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Checking {uuid}")
        infra_url = uuids[uuid]
        info_url = f"https://urlscan.io/result/{uuid}/"
        image_url = f"https://urlscan.io/screenshots/{uuid}.png"
        image_request = requests.get(image_url)
        if image_request.status_code == 200:
            with open("tmp.png", "wb") as f:
                for block in image_request.iter_content(1024):
                    if not block:
                        break
                    f.write(block)
            with open("tmp.png", "rb") as f:
                bytes = f.read()
                sha256 = hashlib.sha256(bytes).hexdigest()
            os.remove("tmp.png")
            # If not a blank page
            if sha256 != "8a8a7e22837dbbf5fae83d0a9306297166408cd8c72b3ec88668c4430310568b":
                results += 1
                print(f"{Fore.GREEN}[RESULT]{Style.RESET_ALL} {infra_url} | {info_url} ")
                if not no_browser:
                    current_links.append(info_url)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Opening {len(current_links)} links found")
    if not no_browser:
        for link in current_links:
            webbrowser.open(link)

def urlscan_submission(url, urlscan_key):
    headers = {"API-Key": urlscan_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": scan_type }
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    sleep(20)
    if response.status_code == 200:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Submitted {url}")
    elif response.status_code == 429:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} We exceeded an API limit for {scan_type} scans. Quitting.")
        quit()
    else:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Encountered an unknown API error. Quitting.")
        quit()
    uuid = response.json()["uuid"]
    uuids.update({uuid: url})
    return 5

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
            if page_number == 1:
                print(f"{Fore.LIGHTRED_EX}[SHODAN]{Style.RESET_ALL} Quitting")
                quit()
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
        urlscan_api = urlscan_submission(url, urlscan_key)
        if urlscan_api == 0:
            quit()
        if urlscan_api == 5:
            continue

def main(shodan_query, shodan_key, urlscan_key):
    shodan_search(shodan_query=shodan_query, shodan_key=shodan_key, urlscan_key=urlscan_key)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Sleeping for 2 minutes to let all of the scans run")
    for i in tqdm(range(120)):
        sleep(1)
    open_links(uuids)

main(shodan_query, shodan_key, urlscan_key)