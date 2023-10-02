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

hashes_to_exclude = [
    "8a8a7e22837dbbf5fae83d0a9306297166408cd8c72b3ec88668c4430310568b", # Blank page
    "3c4c0b07967cc5cfe109e6db12255fd9884f0604f01af81ea65965461db3d7ef",
    "ca70d8d56dc941846c1f2b96467b41e89f2960d11f4b84ce8a5f0498087d3a27",
    "6ae2de5e099b2d7e74bc4a7ffaf242218b434f96211feeac70537a29a140f087",
    "01b478f70ad1c99d929b36ab10d915c9bcfb421db15b1974a83d0bb201f83f94",
    "0a3c2999a3d254b883db327820f8940a7589318d4eff489e8081a1a7d429c1cf",
    "db12f52eb53efdd5ad0040479da16dbdea833f298f384e8b2cbba6a559695cac",
    "e1d22b307642395d75dac6ed503a8548224522d580a25163ca4b62afbb5ee8f5",
    "1dee417d67fa9f4aa304e0daef220ba3dd908ffa7449aebb2a05914133f1668d",
    "ec454a34aeb08d0027da9b5096cec5e1dbabd7effce962a70de6ed63c0e88f7c",
    "bad10f62dd97a830c83fb53656f071ac91f5d57b060fc0c3581498127d42f8c8",
    "f17199ca17ee7377c30e3dfd54390cff1e0596ce99aa3e86fc8817657b8894c4",
    "cfc8ab40848bd3685172b09e729ab2a3d29792024cef4ca1fbd58a6f5e4965a4",
    "837bada6c19361d645eff7b673141c8d3d5e9eee068ad36c82d2dcebdc3708cc",
    "689bd8d295cd24eb6ea2b352046b303b7f4d034cff59360955325e66b519fabc",
    "ce3ee6d7cf58388dff881fd1576e52cf9a9920094e19fc7fe411de7f3c1aa9b9",
    "3a94d793ba948350a99fa85cb17dcce881cad371df1decb027016c43253e7508",
    "b3b78ab610831fc7abb5367e3868e04c075a6afe4f775ac249d91f1ce8d52383",
    "a52f2f18d263d05faf4960f694c860ff898c86d0e434a6d3b7598edf4896ce31",
    "769462f6ff45830c3d8c72bdb5ee6f5b2815eebb4028225bf6c8cce1fd5f3998",
    "1aaed26400f9552f5be74d480b6ac9c3c25291aa5674c79b7e476fa7cbd87ba2"
]

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
    "opendir-cve-2023": "http.title:'Directory listing for' http.html:cve-2023",
    "opendir-exe": "http.title:'Directory listing for' http.html:exe",
    "opendir-docx": "http.title:'Directory listing for' http.html:docx",
    "opendir-bat": "http.title:'Directory listing for' http.html:bat",
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
    hashes = []
    count_of_uuids = len(uuids)
    results = 0
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Analysing {count_of_uuids} URLs")
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} This may take a while since I have to do a lot of hashing")
    for uuid in uuids:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Checking {uuid}")
        infra_url = uuids[uuid]
        info_url = f"https://urlscan.io/result/{uuid}/"
        image_url = f"https://urlscan.io/screenshots/{uuid}.png"
        result_url = f"https://urlscan.io/api/v1/result/{uuid}"
        result_request = requests.get(result_url)
        image_request = requests.get(image_url)
        if image_request.status_code == 200 and result_request.status_code == 200:
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
            if sha256 not in hashes_to_exclude:
                response_codes = []
                result_request = json.loads(result_request.text)
                # This is to remove any 4XX, 5XX responses
                for request_response in result_request["data"]["requests"]:
                    try:
                        response_code = int(request_response["response"]["response"]["status"])
                    except KeyError:
                        continue
                    response_codes.append(response_code)
                if 200 not in response_codes:
                    continue
                results += 1
                print(f"{Fore.GREEN}[RESULT]{Style.RESET_ALL} {infra_url} | {info_url}")
                current_links.append(info_url)
                hashes.append(sha256)
    print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Opening {len(current_links)} links found")
    if not no_browser:
        for link in current_links:
            webbrowser.open(link)
            sleep(20)
    elif no_browser:
        if discord is not None:
            i = 0
            for link in current_links:
                sha256 = hashes[i]
                message = f"Link: {str(link)}\nSHA256: {str(sha256)}"
                DiscordWebhook(url=discord, content=message).execute()
                sleep(1)
                i += 1

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
        try:
            urlscan_api = urlscan_submission(url, urlscan_key)
        except:
            print(f"{Fore.MAGENTA}[URLSCAN]{Style.RESET_ALL} Failed to scan {url}")
            continue
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
    if len(uuids) > 0:
        print(f"{Fore.BLUE}[INFRAHUNTER]{Style.RESET_ALL} Sleeping for 2 minutes to let all of the scans run")
        for i in tqdm(range(120)):
            sleep(1)
        open_links(uuids)

main(shodan_query, shodan_key, urlscan_key)
