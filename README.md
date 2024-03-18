# InfraHunter

Actively hunt for attacker infrastructure by filtering Shodan results with URLScan data.

## Requirements

- Shodan API Key
- URLScan API Key
- `python3 -m pip install -r requirements.txt`

## Usage Examples

`python3 .\hunter.py -q "http.html:'titan stealer'" -s {Shodan API Key} -u {URLScan API Key}`

![Usage Example](assets/usage.png)

### Builtin Queries

You can use pre-built queries by supplying their name with `-q`. To list all builtin queries, run `python .\hunter.py -l`.

`python3 .\hunter.py -s {Shodan API Key} -u {URLScan API Key} -q google-phishing-http-title`

### Discord

You can also provide a URL to a Discord webhook with `-d, --discord`. This will send the results to that webhook instead of opening them in a browser.

## What do I do?

1. Search Shodan with the query provided by `-q, --query`
2. For each combination of IP/port/protocol and domain/port/protocol, submit it to URLScan
    - If it has multiple open ports, all ports will be submitted
    - Submits *http* and *https* URLs
    - Same process for all domains
3. For each URLScan
    - Check to see if the page scanned returned a HTTP OK (200)
    - Check to see if it has an screenshot of the web page in the URLScan results
    - Download the image and calculate its SHA256 and delete the image
    - Check the SHA256 against a list of hashes to exclude (this list is stuff I have deemed non-malicious but plan on making a way to bypass this check) (the list exists because I use this tool to hunt on a schedule)
    - For each remaining result not excluded by the hash check, return the result

## API Rate Limiting

The tool is harcoded to sleep 20 seconds between URLScan submissions to be nice. By default it uses public scans, this can be changed with `--scan-type`.