# InfraHunter

Actively hunt for attacker infrastructure by filtering Shodan results with URLScan data.

## Requirements

- Shodan API Key
- URLScan API Key
- `python3 -m pip install -r requirements.txt`

## Usage Example

`python3 .\hunter.py -q "http.html:'titan stealer'" -s {Shodan API Key} -u {URLScan API Key}`

![Usage Example](assets/usage.png)

## What do I do?

1. Search Shodan with the query provided by `-q, --query`
2. For each IP, submit it to URLScan
    - If it has multiple open ports, all ports will be submitted
    - Submits *http* and *https* URLs
3. Check URLScan for an image from each submission
    - If it has an image, **open in the browser** (opens the URLScan link) and print result to the terminal
    - If not, move to next result

## API Rate Limiting

The builtin rate limits are for **authenticated** accounts and for URLScan. The tool uses ratelimit to manage requests but there is logic built in to handle HTTP 429 codes by switching the scan type. If all scan types are exhausted, the script quits.