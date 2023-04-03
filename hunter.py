from shodan import Shodan
from time import sleep
from tqdm import tqdm
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import argparse, requests, json, webbrowser, hashlib, os
from discord_webhook import DiscordWebhook

colorama_init()

parser = argparse.ArgumentParser(description="Hunt for infrastructure using Shodan and URLScan")
parser.add_argument("-q", "--query", type=str, help="Shodan Query")
parser.add_argument("-s", "--shodan", type=str, help="Shodan API Key")
parser.add_argument("-u", "--urlscan", type=str, help="URLScan API Key")
parser.add_argument("--scan-type", type=str, default="public", help="URL Scan Type (default: Public")
parser.add_argument("--no-browser", action="store_true", help="Do not open a browser")
parser.add_argument("-l", "--list-builtin", action="store_true", help="List Pre-built Shodan Queries")
parser.add_argument("-a", "--auto-all", action="store_true", help="Automatically run all built-in queries")
parser.add_argument("-d", "--discord", type=str, help="Send results to Discord Webhook provided (forces --no-browser)")

args = parser.parse_args()
shodan_key = args.shodan
shodan_query = args.query
urlscan_key = args.urlscan
no_browser = args.no_browser
scan_type = args.scan_type
list_builtin = args.list_builtin
auto_all = args.auto_all
discord = args.discord

if discord is not None:
    if "https" in discord:
        no_browser = True
    else:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Invald Discord Webhook")
        quit()

uuids = {}

buitin_searches = {
    "google-phishing-http-title": "http.title:Google,Gmail http.title:Login port:443,80 -http.html:'with Google'",
    "google-phishing-favicon-hash": "http.favicon.hash:708578229 port:80,443 200 http.title:Login,Signin",
    "microsoft-phishing-http-title": "http.title:Microsoft http.title:Login port:80,443 '200 OK' -http.html:'with Microsoft'",
    "opendir-powershell-1": "http.title:'Directory listing for' http.html:ps1",
    "opendir-cobalt-strike-1": "http.title:'Directory listing for' http.html:cs4.4",
    "opendir-cobalt-strike-2": "http.title:'Directory listing for' http.html:cobaltstrike",
    "opendir-log4shell-1": "http.title:'Directory listing for' http.html:log4shell",
    "opendir-cve-2022": "http.title:'Directory listing for' http.html:cve-2022",
    "generic-ransomware-1": "http.html:'files have been encrypted'",
    "generic-infostealer-1": "http.title:stealer http.html:login"
}

def list_all():
    if list_builtin:
        for name in buitin_searches:
            print(f"Name: {name}")
            print("Shodan Query: " + str(buitin_searches[name]))
            print()

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
                current_links.append(info_url)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Opening {len(current_links)} links found")
    if not no_browser:
        for link in current_links:
            webbrowser.open(link)
            sleep(20)
    elif no_browser:
        if not discord is None:
            for link in current_links:
                DiscordWebhook(url=discord, content=link).execute()

def urlscan_submission(url, urlscan_key):
    headers = {"API-Key": urlscan_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": scan_type }
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    try:
        sleep(20)
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Received a KeyboardInterrupt")
        quit()
    if response.status_code == 200:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Scanning {url}")
        uuid = response.json()["uuid"]
        uuids.update({uuid: url})
    elif response.status_code == 429:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} We exceeded an API limit for {scan_type} scans")
        quit()
    elif response.status_code == 400:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Failed to scan {url}")
    else:
        print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Encountered an unknown API error")
    return 5

def shodan_search(shodan_query, shodan_key, urlscan_key):
    if shodan_query in buitin_searches:
        shodan_query = buitin_searches[shodan_query]
    api = Shodan(shodan_key)
    results_to_analyze = set()
    total_results = 0
    print(f"{Fore.LIGHTRED_EX}[SHODAN]{Style.RESET_ALL} Search: {shodan_query}")
    try:
        for result in api.search_cursor(shodan_query):
            total_results += 1
            ip = str(result["ip_str"])
            port = str(result["port"])
            url = f"http://{ip}:{port}"
            url_tls = f"https://{ip}:{port}"
            results_to_analyze.add(url)
            results_to_analyze.add(url_tls)
            domains = result["hostnames"]
            if len(domains) > 0:
                for domain in domains:
                    url = f"http://{domain}:{port}"
                    url_tls = f"https://{domain}:{port}"
                    results_to_analyze.add(url)
                    results_to_analyze.add(url_tls)
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Received a KeyboardInterrupt")
        quit()
    urls_to_analyze = len(results_to_analyze)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Results Found: {total_results}")
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} URLs to Analyze: {urls_to_analyze}")
    for url in results_to_analyze:
        urlscan_api = urlscan_submission(url, urlscan_key)
        if urlscan_api == 0:
            quit()
        if urlscan_api == 5:
            continue

def main(shodan_query, shodan_key, urlscan_key):
    if list_builtin:
        list_all()
        quit()
    if shodan_key == None:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Missing Shodan API Key")
        return
    if urlscan_key == None:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Missing URLScan API Key")
        return
    if auto_all:
        for name in buitin_searches:
            shodan_query = buitin_searches[name]
            shodan_search(shodan_query=shodan_query, shodan_key=shodan_key, urlscan_key=urlscan_key)
    else:
        if shodan_query == None:
            print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Missing Shodan Query")
            return
        shodan_search(shodan_query=shodan_query, shodan_key=shodan_key, urlscan_key=urlscan_key)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Sleeping for 2 minutes to let all of the scans run")
    for i in tqdm(range(120)):
        sleep(1)
    open_links(uuids)

main(shodan_query, shodan_key, urlscan_key)