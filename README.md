# SQLmapAutomatizer
SQLmap Automatizer

## Usage

python SQLmapAutomatizer.py 
--targets TARGETS 
[--output OUTPUT] 
[--cookie-file COOKIE_FILE] 
[--level LEVEL] 
[--risk RISK] 
[--log-file LOG_FILE]

Example:

python3 SQLmapAutomatizer.py \
  --targets targets.txt \
  --output report.csv \
  --cookie-file=cookies.txt \
  --level 3 \
  --risk 1 \
  --log-file sqlmap.log

NOTE: Cookies are acceptable only without spaces!

## Targets example

cat targets.txt
https://example.com/page.php?id=5|id

NOTE: Need separator {ULR} | {parameter}

For quicker validation we can use additional option of sqlmap like:
```
--dbms=postgres
```
inside:

```
cmd = [
    "sqlmap",
    "-u", full_url,
    "-p", param,
    "--batch",
    "-v", "0",
    "--level", str(level),
    "--risk", str(risk),
    "--disable-coloring",
    "--output-dir=/tmp/sqlmap-output"
]
```
