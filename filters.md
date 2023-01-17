# Shodan Search Filters

This is a live document containing search filters I have found at least slightly reliable to find infrastructure.

- OpenDir
    - `http.title:'Directory listing for'`

- Cobalt Strike Files
    - `http.title:'Directory listing for' http.html:cs4.4`
    - `"http.title:'Directory listing for' http.html:cobaltstrike"`

- Potential Log4Shell Scanners
    - `"http.title:'Directory listing for' http.html:log4shell"`

- Misc.
    - `http.title:"Directory listing for" http.html:cve-2022`