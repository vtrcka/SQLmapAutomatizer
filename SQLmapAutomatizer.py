import subprocess
import csv
import argparse
from pathlib import Path
import logging
import sys
import re

REDIRECT_KEYWORDS = [
    "got a 302 redirect to",
    "rdPage.aspx?rdReport=Messages.Success"
]

def setup_logging(log_path=None):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if log_path:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(formatter)
        logger.addHandler(fh)


def extract_line(output, keyword):
    for line in output.splitlines():
        if keyword.lower() in line.lower():
            parts = line.split(":", 1)
            return parts[1].strip() if len(parts) > 1 else ""
    return ""


def clean_cookies(cookie_file_path):
    try:
        with open(cookie_file_path, 'r') as f:
            raw = f.read()
            cleaned = raw.replace('\n', '').replace('\r', '').replace(' ', '').strip()
            logging.info(f"Using cleaned cookies: {cleaned}")
            return cleaned
    except Exception as e:
        logging.error(f"Failed to read or clean cookies: {e}")
        return None


def check_redirect_warnings(output):
    for keyword in REDIRECT_KEYWORDS:
        if keyword.lower() in output.lower():
            return True
    return False


def prompt_cookie_change(current_cookie, full_url):
    print(f"\n[!] Warning: Possible false positive or login redirect detected.")
    print(f"URL: {full_url}")
    print("Cookie might be invalid or session expired.\n")

    new_cookie = input("Press Enter to continue with same cookie...\nOr paste a new cookie (e.g., sessionid=abc123;csrftoken=xyz):\n> ").strip()

    if new_cookie:
        logging.info("Using new user-provided cookie.")
        return new_cookie
    else:
        logging.info("Continuing with original cookie.")
        return current_cookie


def extract_techniques(output):
    techniques = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("Type:"):
            type_line = lines[i].strip()
            title_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
            payload_line = lines[i + 2].strip() if i + 2 < len(lines) else ""

            technique = f"{type_line} | {title_line} | {payload_line}"
            techniques.append(technique)
            i += 3
        else:
            i += 1
    return "\n".join(techniques)


def run_sqlmap(full_url, param, level, risk, cookie_string):
    while True:
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

        if cookie_string:
            cmd.extend(["--cookie", cookie_string])

        logging.info(f"Running sqlmap for: {full_url} (param: {param})")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        output = ""
        for line in process.stdout:
            sys.stdout.write(line)
            output += line

        process.wait()

        if check_redirect_warnings(output):
            cookie_string = prompt_cookie_change(cookie_string, full_url)
            continue  # retry with updated cookie
        else:
            break  # continue processing

    if "back-end DBMS" in output:
        status = "VULNERABLE"
        dbms = extract_line(output, "back-end DBMS")
        os = extract_line(output, "operating system")
        techs = extract_line(output, "web application technology")
        technique_details = extract_techniques(output)
    else:
        status = "NOT VULNERABLE"
        dbms = os = techs = technique_details = ""

    logging.info(f"Result: {status}, DBMS: {dbms}, OS: {os}, Techs: {techs}")
    return full_url, param, status, dbms, os, techs, technique_details


def main():
    parser = argparse.ArgumentParser(description="Batch sqlmap scanner with CSV output")
    parser.add_argument("--targets", required=True, help="File with targets (format: url|param)")
    parser.add_argument("--output", default="sqlmap_results.csv", help="CSV output file")
    parser.add_argument("--cookie-file", help="Path to cookie file (optional)")
    parser.add_argument("--level", type=int, default=1, help="Sqlmap level (default: 1)")
    parser.add_argument("--risk", type=int, default=1, help="Sqlmap risk (default: 1)")
    parser.add_argument("--log-file", help="Path to sqlmap_batch log file")

    args = parser.parse_args()
    setup_logging(args.log_file)

    cookie_string = clean_cookies(args.cookie_file) if args.cookie_file else None

    targets_file = Path(args.targets)
    if not targets_file.exists():
        logging.error(f"Target file not found: {targets_file}")
        return

    with open(args.output, "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["target", "param", "status", "dbms", "os", "webapp_techs", "techniques"])

        with open(targets_file) as f:
            for line in f:
                line = line.strip()
                if not line or '|' not in line:
                    continue

                full_url, param = line.split('|', 1)
                target, param, status, dbms, os, techs, techniques = run_sqlmap(
                    full_url, param, args.level, args.risk, cookie_string
                )

                writer.writerow([target, param, status, dbms, os, techs, techniques])

    logging.info(f"Scan complete. Results saved to {args.output}")


if __name__ == "__main__":
    main()
