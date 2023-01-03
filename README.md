# InfraHunter

Actively hunt for attacker infrastructure by filtering Shodan results with URLScan data.

## Requirements

- Shodan API Key
- URLScan API Key

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

## API Considerations

To be overly conservative with rate limits, it is rate limited to 1 request per 20 seconds. Keep in mind that the free Shodan account has a limit of 100 queries per month. In other words, I'd suggest using specific searches to avoid buring through API credits.

### The Math

I chose 1/20 req/sec based on simple math from the URLScan limit policy for an entire day.

- URLScan Public Scan Limit Per Day = 5000
- Minutes in a Day = 1440

`5000/1440 = 3.5`
- Do not exceed 3 scans per minute.

- 60 seconds / 3 scans = 20 seconds / scan