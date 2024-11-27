"""Website backend file"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from functools import wraps

import dns
import dns.asyncresolver
import dns.resolver
import requests
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    render_template,
    send_from_directory,
    request,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.wrappers import Request as WerkzeugRequest

CACHE_FILE = "cloudflare_ips.cache"
CACHE_DURATION = 60 * 60 * 24  # 24 hours

MAX_CONCURRENT_QUERIES = 10

STATIC_FOLDER = "static"

SELECTED_RDATA_TYPES = [
    "A", "AAAA", "AFSDB", "APL", "AXFR", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME",
    "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO", 
    "HIP", "HTTPS", "IPSECKEY", "IXFR", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", 
    "NSEC3", "NSEC3PARAM", "NSEC", "NXT", "OPENPGPKEY", "OPT", "PTR", "RP", "RRSIG", 
    "SIG", "SMIMEA", "SOA", "SPF", "SSHFP", "SVCB", "SRV", "TA", "TKEY", "TLSA", 
    "TSIG", "TXT", "URI", "ZONEMD"
] # List of most commonly used types (not actually all, thats just too much D:)

ips_being_used = []


# Create the flask app
app = Flask(__name__)

# Create a limiter instance
limiter = Limiter(get_remote_address, app=app, default_limits=["3 per second"])


def disable_same_ip_concurrency(func):
    """Make it so each ip can only have one request processing at a time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        if ip in ips_being_used:
            abort(429)  # Forbidden
        ips_being_used.append(ip)
        try:
            return func(*args, **kwargs)
        finally:
            ips_being_used.remove(ip)

    return wrapper


def split_and_strip_str(string):
    """Split a string into lists and stip each one"""
    return [substr.strip() for substr in string.split()]


def get_cloudflare_ips():
    """Get all ips that belong to cloudflare using a cache"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            cache_time, ipv4, ipv6 = f.read().split("---")
            cache_time, ipv4, ipv6 = (
                cache_time.strip(),
                split_and_strip_str(ipv4),
                split_and_strip_str(ipv6),
            )
        if time.time() - float(cache_time) < CACHE_DURATION:
            return ipv4, ipv6

    try:
        cloudflare_ipv4 = requests.get(
            "https://www.cloudflare.com/ips-v4", timeout=5
        ).text.split("\n")
        cloudflare_ipv6 = requests.get(
            "https://www.cloudflare.com/ips-v6", timeout=5
        ).text.split("\n")
    except requests.RequestException as e:
        print(f"Error fetching Cloudflare IPs: {e}")
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache_time, ipv4, ipv6 = f.read().split("---")
                ipv4, ipv6 = split_and_strip_str(ipv4), split_and_strip_str(ipv6)
            return ipv4, ipv6
        else:
            logging.critical(
                "Unable to fetch cloudflare IP ranges and no cache is available. Aborting..."
            )
            sys.exit(1)

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        f.write(f"{time.time()}\n---\n")
        f.write("\n".join(cloudflare_ipv4) + "\n---\n")
        f.write("\n".join(cloudflare_ipv6))

    return cloudflare_ipv4, cloudflare_ipv6


# Get Cloudflare IPs
cf_ipv4, cf_ipv6 = get_cloudflare_ips()

# Load the list of nameservers from a JSON file
with open("dns_servers.json", "r", encoding="utf8") as file:
    nameserver_list = json.load(file)

# Make a resolver for each nameserver
resolvers = {}
for name, nameserver in nameserver_list.items():
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.cache = dns.resolver.Cache(10)
    resolver.timeout = 2
    resolver.lifetime = 2
    resolver.nameservers = nameserver
    resolvers[name] = resolver


def handle_cloudflare_request(req):
    """Handle a cloudflare request and set needed environ flags"""
    # Extract Cloudflare headers
    ip = req.headers.get("Cf-Connecting-IP", None)
    ipv6 = req.headers.get("Cf-Connecting-IPv6", None)
    country = req.headers.get("Cf-Ipcountry", None)

    is_ipv4 = ip and (":" not in ip)

    # I do not need to detect this, atleast not with cloudflared.exe (its always cloudflare)
    # req.environ['cf_addr'] = req.remote_addr
    # req.environ['cf_request'] = True

    # Store Cloudflare details in WSGI environ for future access
    req.environ["REMOTE_ADDR"] = (
        ip if ip and is_ipv4 else (ipv6 if ipv6 else req.remote_addr)
    )  # Use IPv4 if available, else use IPv6 (fallback to remote_addr if the request is local)
    req.environ["country"] = country


class CloudflareMiddleware:
    """Middleware for the Werkzeug app to process Cloudflare headers"""
    def __init__(self, wz_app):
        self.app = wz_app

    def __call__(self, environ, start_response):
        # Create a Werkzeug request object from the WSGI environment
        req = WerkzeugRequest(environ)

        # Handle Cloudflare request
        handle_cloudflare_request(req)

        # Proceed with the rest of the request
        return self.app(environ, start_response)


def is_cloudflare_request(remote_addr):
    """Make sure the request is comming from cloudflare"""
    # Check if remote_addr is in the Cloudflare IP ranges
    try:
        ip = ipaddress.ip_address(remote_addr)
        return any(ip in ipaddress.ip_network(net) for net in cf_ipv4 + cf_ipv6)
    except ValueError:
        return False


def is_valid_dns_query(query: str, allow_wildcard: bool = True) -> bool:
    """Check if the dns query parameter is valid"""
    # Remove the leading "*." for validation (if it exists)
    if allow_wildcard and query.startswith("*."):
        query = query[2:]
    # Regex for a valid DNS query (excluding wildcards)
    pattern = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
    if len(query.split(".")) < 2:
        return False
    # Check the total length of the domain name
    if len(query) > 253:
        return False
    # Use regex to match the pattern
    if not pattern.match(query):
        return False
    return True


async def query_single_type(semaphore, domain, query_type, dns_resolver):
    """Query a single DNS record type for a given domain using the provided resolver."""
    async with semaphore:
        try:
            start_time = time.perf_counter()
            response = await dns_resolver.resolve(domain, query_type)
            end_time = time.perf_counter()
            return {
                "type": query_type,  # dns.rdatatype.to_text(query_type)
                "owner": response.canonical_name.relativize(domain).to_text(
                    omit_final_dot=True
                ),
                "data": [str(rdata) for rdata in response],
                "expiry": response.expiration,
                "ping": round((end_time - start_time) * 1000, 2),
            }
        except dns.exception.DNSException as e:
            if e == "DNS metaqueries are not allowed.":
                return {"error": "ratelimited"}
            return None


async def query_domain_multi_nameserver(domain, rdata_types, ns_list):
    """Query a domain for all DNS record types concurrently across all nameservers."""
    # Prepare the semaphore for limiting concurrent requests
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)

    # Prepare tasks for each nameserver and each DNS record type
    tasks = []
    for nameserver_name in ns_list.keys():
        # Create a task for each record type and nameserver
        dns_resolver = resolvers[nameserver_name]
        for record_type in rdata_types:
            tasks.append(
                query_single_type(semaphore, domain, record_type, dns_resolver)
            )

    # Run all tasks concurrently and gather the results
    results = await asyncio.gather(*tasks)

    # Organize results by nameserver and record type
    organized_results = {}
    for idx, (nameserver_name, _) in enumerate(ns_list.items()):
        organized_results[nameserver_name] = [
            result
            for result in results[idx * len(rdata_types) : (idx + 1) * len(rdata_types)]
            if result
        ]

    return organized_results


def compare_responses(results):
    """Compare results and return the comparison"""
    record_sets = defaultdict(
        lambda: defaultdict(lambda: {"data": set(), "owner": set(), "expiry": set()})
    )
    nameservers = list(results.keys())

    # Collect all unique records along with their owner and expiration information
    for ns, records in results.items():
        for record in records:
            if "error" in record:
                continue

            record_type = record["type"]
            data_key = tuple(sorted(record["data"]))

            # Collect data, owner, and expiry information
            record_sets[record_type][data_key]["data"].add(ns)
            record_sets[record_type][data_key]["owner"].add(record["owner"])
            record_sets[record_type][data_key]["expiry"].add(record["expiry"])

    comparison = {"matching": {}, "outliers": defaultdict(dict)}

    # Identify matching records and outliers, including owner and expiration info
    for record_type, data_sets in record_sets.items():
        if len(data_sets) == 1:
            # All nameservers agree
            data_key = list(data_sets.keys())[0]
            data_info = data_sets[data_key]
            comparison["matching"][record_type] = {
                "data": list(data_key),
                "expiry": list(data_info["expiry"]),
                "owner": data_info["owner"].pop(),
                "full_match": True,
            }
        else:
            # There are outliers
            max_agreement = max(len(info["data"]) for info in data_sets.values())
            for data_key, data_info in data_sets.items():
                if len(data_info["data"]) == max_agreement:
                    comparison["matching"][record_type] = {
                        "data": list(data_key),
                        "expiry": list(data_info["expiry"]),
                        "owner": data_info["owner"].pop(),
                        "full_match": len(data_info["data"]) == len(nameservers),
                        "agreeing_nameservers": list(data_info["data"]),
                        "total_nameservers": len(nameservers),
                    }
                else:
                    comparison["outliers"][record_type][
                        ", ".join(data_info["data"])
                    ] = {
                        "data": list(data_key),
                        "expiry": list(data_info["expiry"]),
                        "owner": data_info["owner"].pop(),
                    }

    return comparison


def get_found_records(results):
    """Get all found records from the results"""
    record_types = []
    for _, ns in results.items():
        for record in ns:
            record_type = record["type"]
            if record_type not in record_types:
                record_types.append(record_type)
    return record_types


def formatted_country():
    """Return a the country as a string"""
    country = request.environ.get("country")
    return country if country else "N/A"


@app.route("/dns-query", methods=["POST"])
@limiter.limit("8 per minute")
@disable_same_ip_concurrency
def dns_query():
    """Regular dns query"""
    chosen_domain = request.json.get("domain")
    if is_valid_dns_query(chosen_domain):
        print(f"{request.remote_addr} {formatted_country()} - QUERY - {chosen_domain}")
        results = asyncio.run(
            query_domain_multi_nameserver(
                chosen_domain, SELECTED_RDATA_TYPES, nameserver_list
            )
        )
        comparison = compare_responses(results)
        return jsonify(
            {
                "results": results,
                "comparison": comparison,
                "types": get_found_records(results),
            }
        )
    print(f"BLOCKED - {request.remote_addr} {formatted_country()} - QUERY - {chosen_domain}")
    return make_response(jsonify({"error": "Invalid domain"}), 400)


@app.route("/dns-requery", methods=["POST"])
@limiter.limit("20 per minute")
@disable_same_ip_concurrency
def dns_requery():
    """Requery a set of dns record"""
    chosen_domain = request.json.get("domain")
    chosen_rdata_types = request.json.get("types", [])
    filtered_rdata_types = list(
        {rdata_type for rdata_type in chosen_rdata_types if rdata_type in SELECTED_RDATA_TYPES}
    )
    if is_valid_dns_query(chosen_domain):
        if not filtered_rdata_types:
            return make_response(jsonify({"error": "Invalid query types"}), 400)
        print(
            f"{request.remote_addr} {formatted_country()} - REQUERY - " \
            f"Amount: {len(filtered_rdata_types)} - {chosen_domain}"
        )
        results = asyncio.run(
            query_domain_multi_nameserver(
                chosen_domain, filtered_rdata_types, nameserver_list
            )
        )
        comparison = compare_responses(results)
        return jsonify(
            {
                "results": results,
                "comparison": comparison,
                "types": get_found_records(results),
            }
        )
    print(
        f"BLOCKED - {request.remote_addr} {formatted_country()} - REQUERY - " \
        f"Amount: {len(filtered_rdata_types)} - {chosen_domain}"
    )
    return make_response(jsonify({"error": "Invalid domain"}), 400)


@app.route("/", methods=["GET"])
def index():
    """Root website page"""
    return render_template(
        "index.html",
        nameserver_list=nameserver_list,
        rdata_types=SELECTED_RDATA_TYPES,
    )


@app.route("/static/<path:path>", methods=["GET"])
def static_serve(path):
    """Serve a static file with caching"""
    response = make_response(send_from_directory(STATIC_FOLDER, path))
    response.headers["Cache-Control"] = "public, max-age=54000"  # Add a 15 minute cache
    return response


@app.route("/favicon.ico", methods=["GET"])
def static_favicon():
    """Serve a the favicon with caching"""
    response = make_response(send_from_directory(STATIC_FOLDER, "favicon.ico"))
    response.headers["Cache-Control"] = "public, max-age=54000"  # Add a 15 minute cache
    return response


# @app.before_request
# def before_request_handler():
#     request.country = request.environ.get("country")
#     print(f"Request is from: {request.country}")

if __name__ == "__main__":
    # Wrap the Flask app with the middleware
    app.wsgi_app = CloudflareMiddleware(app.wsgi_app)

    # Run the flask app
    app.run("0.0.0.0", port=8080, debug=False)
