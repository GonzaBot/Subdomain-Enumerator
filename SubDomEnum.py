#!/usr/bin/env python3
"""
SubDomEnum.py - Subdomain Enumerator


Techniques:
  - Brute force via DNS resolution (built-in wordlist de 1500+ palabras + externa)
  - Certificate Transparency logs (crt.sh)
  - Live validation (HTTP/HTTPS reachability check)

Author: Gonza
"""

import argparse
import socket
import sys
import json
import csv
import time
import datetime
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install requests rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────────────────────
# WORDLIST — 1500+ palabras reales usadas en pentests
# ─────────────────────────────────────────────────────────────
BUILTIN_WORDLIST = [
    # Web / Frontend
    "www","www1","www2","www3","www4","www5","web","web1","web2","web3","web4",
    "site","sites","home","homepage","landing","portal","app","apps","application",
    "applications","spa","pwa","frontend","front","ui","ux",

    # APIs
    "api","api1","api2","api3","api4","apiv1","apiv2","apiv3","apis",
    "rest","restapi","graphql","grpc","gateway","api-gateway","apigateway",
    "v1","v2","v3","v4","endpoint","endpoints","service","services",
    "microservice","microservices","backend","internal-api","external-api",
    "public-api","private-api","open-api","developer","developers","dev-api",

    # Auth / Identity
    "auth","auth1","auth2","authentication","authorize","authorization",
    "oauth","oauth2","sso","saml","login","logout","signin","signup",
    "register","password","reset","forgot","verify","verification",
    "identity","id","ids","iam","idp","keycloak","okta","ping",
    "accounts","account","profile","profiles","user","users","me",
    "session","sessions","token","tokens","jwt","mfa","2fa","otp",

    # Admin / Management
    "admin","admin1","admin2","admin3","administrator","administration",
    "manage","manager","management","panel","control","controlpanel",
    "cp","cpanel","whm","plesk","directadmin","webmin","dashboard",
    "dash","console","sysconsole","sysadmin","superadmin","root",
    "backoffice","back-office","staff","internal","ops","operations",
    "helpdesk","servicedesk","desk","support","ticket","tickets","crm","erp",

    # Dev / Staging / Testing
    "dev","dev1","dev2","dev3","dev4","develop","developer","development",
    "staging","stage","stg","stg1","stg2","stg3","stag",
    "test","test1","test2","test3","test4","testing","tst",
    "uat","uat1","uat2","uat3","qa","qa1","qa2","qa3","qc",
    "preprod","pre-prod","pre","prod","production","prd","live",
    "alpha","beta","rc","release","hotfix","feature","sandbox",
    "sandbox1","sandbox2","lab","labs","demo","demos","poc","prototype",
    "local","localhost","int","integration","integrations","canary",
    "preview","experiment","nightly","trunk",

    # Mail
    "mail","mail1","mail2","mail3","mail4","mail5","email","emails",
    "smtp","smtp1","smtp2","smtp3","smtp-relay","smtpout","smtpin",
    "pop","pop3","imap","imap2","webmail","webmail1","webmail2",
    "mx","mx1","mx2","mx3","mx4","mx5","relay","mailrelay",
    "mailserver","exchange","owa","autodiscover","autoconfig",
    "lists","list","newsletter","mailman","postfix","sendmail",
    "spam","spamfilter","antispam","filter","quarantine",

    # DNS / Network infra
    "ns","ns1","ns2","ns3","ns4","ns5","ns6","ns7","ns8",
    "dns","dns1","dns2","dns3","dns4","resolver","nameserver",
    "ntp","ntp1","ntp2","time","whois","rdns","ptr",

    # CDN / Static / Media
    "cdn","cdn1","cdn2","cdn3","static","static1","static2","assets",
    "asset","media","media1","media2","img","images","image","pics",
    "photos","photo","thumbs","thumbnails","avatar","avatars",
    "files","file","docs","documents","download","downloads","dl",
    "upload","uploads","content","contents","resources","res",
    "public","pub","data","storage","store","bucket","blob","s3",

    # Cloud / Infrastructure
    "cloud","aws","azure","gcp","gke","eks","aks","heroku","digitalocean",
    "linode","vultr","hetzner","ovh","rack","rackspace","cloudflare",
    "lambda","functions","serverless","edge","edge1","edge2","pop1","pop2",

    # DevOps / CI-CD
    "ci","cd","cicd","build","builds","builder","deploy","deployment",
    "deployments","release","releases","pipeline","pipelines","jenkins",
    "gitlab","github","bitbucket","git","git1","git2","svn","cvs","tfs",
    "artifactory","nexus","registry","docker","dockerhub","harbor",
    "k8s","kubernetes","helm","rancher","openshift","nomad","consul",
    "vault","terraform","ansible","puppet","chef","saltstack",
    "sonar","sonarqube","selenium","browserstack","saucelabs",

    # Monitoring / Observability
    "monitor","monitoring","monitor1","mon","mon1","mon2",
    "grafana","kibana","elastic","elasticsearch","logstash","beats",
    "prometheus","alertmanager","thanos","cortex","loki","tempo",
    "zabbix","nagios","icinga","checkmk","datadog","newrelic","dynatrace",
    "splunk","graylog","fluentd","fluentbit","jaeger","zipkin","otel",
    "apm","trace","traces","metrics","logs","logging","alerts","alert",
    "status","status1","statuspage","uptime","health","healthcheck","ping",
    "stats","statistics","analytics","ga","gtm","matomo","mixpanel",

    # Database
    "db","db1","db2","db3","db4","database","databases","data1","data2",
    "mysql","mysql1","mysql2","postgres","postgresql","pg","pg1","pg2",
    "mssql","sqlserver","sql","oracle","mongo","mongodb","redis","redis1",
    "redis2","memcached","cassandra","dynamodb","couchdb","couchbase",
    "elasticsearch2","neo4j","influxdb","clickhouse","snowflake","bigquery",
    "rds","aurora","mariadb","sqlite","phpmyadmin","adminer","pgadmin",
    "dbadmin","dba","replica","primary","secondary","master","slave",
    "read","write","readreplica","readonly","standby","backup-db",

    # Cache / Queue / Messaging
    "cache","cache1","cache2","queue","queues","worker","workers",
    "rabbitmq","kafka","activemq","sqs","pubsub","nats","mqtt",
    "celery","sidekiq","resque","bull","bee","beanstalk",

    # Security
    "security","sec","secure","ssl","tls","cert","certs","certificate",
    "waf","ids","ips","firewall","fw","fw1","fw2","dmz",
    "vpn","vpn1","vpn2","vpn3","openvpn","wireguard","ovpn","ipsec",
    "proxy","proxy1","proxy2","squid","haproxy","nginx-proxy",
    "bastion","jump","jumpbox","jump1","bastion1","bastion2",
    "siem","soc","noc","pentest","scanner","scan","audit","compliance",
    "sentry","bugsnag","rollbar","errortracking",

    # File / Collaboration
    "share","shared","sharepoint","onedrive","gdrive","drive","box",
    "dropbox","nextcloud","owncloud","confluence","wiki","wikis","notion",
    "jira","trello","asana","monday","clickup","basecamp","teamwork",
    "slack","teams","chat","im","messaging","collab","collaborate",
    "docs","doc","document","documents","sheets","presentation",

    # CMS / Blog
    "blog","blogs","blog1","news","press","media3","magazine","journal",
    "wordpress","wp","wp-admin","wp-login","drupal","joomla","typo3",
    "ghost","strapi","contentful","sanity","prismic","craft","webflow",
    "cms","cms1","cms2","content2","editorial","publish","publisher",

    # E-commerce
    "shop","shop1","shop2","store","store1","ecommerce","commerce",
    "checkout","cart","basket","payment","payments","pay","pay1","pay2",
    "billing","invoice","invoices","orders","order","catalog","catalogue",
    "products","product","inventory","stock","warehouse","logistics",
    "shipping","returns","refunds","promo","coupon","coupons","deals",
    "magento","woocommerce","shopify","prestashop","opencart","bigcommerce",

    # Customer / Support
    "customer","customers","client","clients","partner","partners",
    "affiliate","affiliates","reseller","resellers","vendor","vendors",
    "b2b","b2c","crm2","salesforce","hubspot","zendesk","freshdesk",
    "intercom","livechat","help","helpdesk2","faq","kb","knowledgebase",
    "community","forum","forums","discuss","discourse","reddit","board",

    # Mobile
    "mobile","mobile1","mobile2","m","m1","m2","wap","app2","apps2",
    "android","ios","push","pushnotification","fcm","apns","deeplink",

    # Video / Media streaming
    "video","video1","video2","videos","stream","streaming","stream1",
    "live2","broadcast","media4","hls","dash","vod","rtmp","wowza",
    "youtube","vimeo","twitch","zoom","meet","meet1","meet2","webrtc",

    # Business / Corporate
    "corporate","corp","company","office","office1","office2","hq",
    "headquarters","intranet","intranet1","extranet","hr","hr2","payroll",
    "finance","accounting","legal","compliance2","privacy","gdpr",
    "investor","investors","ir","press2","careers","jobs","recruiting",
    "marketing","sales","crm3","leads","reports","reporting","bi",
    "businessintelligence","erp2","sap","oracle2","workday","adp",

    # IoT / Industrial
    "iot","device","devices","sensor","sensors","gateway2","mqtt2",
    "scada","plc","hmi","industrial","opc","modbus","influx",

    # Geographic / Regional
    "us","eu","uk","de","fr","es","it","br","au","ca","mx","in","jp","cn",
    "ap","asia","america","europe","latam","global","international","local2",
    "east","west","north","south","central","us-east","us-west","eu-west",
    "us-east-1","us-west-2","eu-central-1","ap-southeast-1",

    # Networking / Infra hardware
    "router","router1","router2","switch","switch1","ap","wifi","wireless",
    "vpn-gateway","nat","dhcp","radius","tacacs","ldap","ldap1","ldap2",
    "ad","ad1","dc","dc1","dc2","dc3","exchange2","exchange3",
    "mgmt","management2","ilo","ipmi","idrac","alom","bmc",
    "noc2","ops2","netops","netmon","netflow","sflow","snmp",

    # Backup / DR
    "backup","backup1","backup2","backups","dr","disaster","recovery",
    "drsite","drtest","failover","replica2","archive","archives","cold",

    # Misc common
    "new","old","legacy","deprecated","temp","tmp","scratch","test5",
    "demo2","sandbox3","lab2","research","r&d","rd","innovation",
    "open","public2","ext","external","shared2","common","core",
    "platform","platforms","infra","infrastructure","system","systems",
    "server","server1","server2","server3","host","host1","host2",
    "node","node1","node2","node3","node4","cluster","cluster1",
    "lb","loadbalancer","load-balancer","haproxy2","nginx","apache",
    "web-proxy","reverse-proxy","forward-proxy","socks",
    "printer","print","fax","pbx","voip","sip","sip1","asterisk",
    "tv","iptv","radio","rss","feed","feeds","sitemap","robots",
    "ping2","trace","traceroute","speedtest","test-speed",
    "redirect","shortlink","short","link","links","url","urls",
    "cron","scheduler","scheduler1","task","tasks","jobs2","worker2",

    # Numbers — variaciones numéricas comunes
    "1","2","3","01","02","03","001","002","003",
    "10","11","12","20","21","22","100","200","404",
]

# ─────────────────────────────────────────────────────────────
# DNS RESOLUTION
# ─────────────────────────────────────────────────────────────
def resolve_subdomain(subdomain: str) -> dict | None:
    try:
        results = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC)
        ips = list(set(r[4][0] for r in results))
        return {"subdomain": subdomain, "ips": ips, "source": "bruteforce"}
    except (socket.gaierror, socket.herror, OSError):
        return None


# ─────────────────────────────────────────────────────────────
# CERTIFICATE TRANSPARENCY (crt.sh)
# ─────────────────────────────────────────────────────────────
def fetch_crtsh(domain: str) -> list[str]:
    subdomains = set()
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=.{domain}&output=json",
    ]
    for url in urls:
        try:
            resp = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 SubDomEnum/1.0"},
            )
            if resp.status_code == 200 and resp.text.strip():
                try:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub.endswith(f".{domain}") and sub != domain and " " not in sub:
                                subdomains.add(sub)
                except Exception:
                    pass
        except requests.exceptions.Timeout:
            console.print("  [yellow]⚠[/yellow]  crt.sh timeout — continuando sin CT logs")
        except Exception as e:
            console.print(f"  [yellow]⚠[/yellow]  crt.sh error: {e}")

    return list(subdomains)


# ─────────────────────────────────────────────────────────────
# LIVE VALIDATION
# ─────────────────────────────────────────────────────────────
def check_live(subdomain: str, timeout: int = 5) -> dict:
    result = {"http": False, "https": False, "status_code": None, "title": None, "redirect": None}

    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SubDomEnum/1.0)"},
                verify=False,
            )
            result[scheme] = True
            result["status_code"] = resp.status_code
            final_url = resp.url
            if final_url not in (f"{scheme}://{subdomain}", f"{scheme}://{subdomain}/"):
                result["redirect"] = final_url
            title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["title"] = title_match.group(1).strip()[:80]
            break
        except Exception:
            pass

    return result


# ─────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────
def generate_html_report(domain: str, results: list[dict], stats: dict) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_count = sum(1 for r in results if r.get("live"))
    found_count = len(results)

    rows = ""
    for r in results:
        live_badge = '<span class="badge live">LIVE</span>' if r.get("live") else '<span class="badge dead">DNS ONLY</span>'
        status = r.get("status_code", "-") or "-"
        status_class = "ok" if str(status).startswith("2") else "warn" if str(status).startswith("3") else "err"
        ips = ", ".join(r.get("ips", [])) or "-"
        title = r.get("title") or "-"
        src = r.get("source", "bruteforce")
        source_badge = f'<span class="src src-{src}">{src.upper()}</span>'
        rows += f"""
        <tr>
            <td><code>{r['subdomain']}</code></td>
            <td>{live_badge}</td>
            <td><span class="status {status_class}">{status}</span></td>
            <td>{ips}</td>
            <td class="title-cell" title="{title}">{title}</td>
            <td>{source_badge}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SubDomEnum :: {domain}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{
    --bg:#0a0c10;--bg2:#111318;--bg3:#1a1d24;--border:#2a2d35;
    --accent:#00ff9d;--accent2:#00b8ff;--accent3:#ff4757;--accent4:#ffa502;
    --text:#e2e8f0;--text-dim:#64748b;
    --font-mono:'JetBrains Mono',monospace;--font-display:'Syne',sans-serif;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:var(--font-mono);min-height:100vh;padding:2rem}}
  .header{{border-left:4px solid var(--accent);padding:1.5rem 2rem;background:var(--bg2);border-radius:0 8px 8px 0;margin-bottom:2rem}}
  .header h1{{font-family:var(--font-display);font-size:2rem;font-weight:800;color:var(--accent);letter-spacing:-1px}}
  .header h1 span{{color:var(--text-dim);font-weight:400}}
  .header .meta{{color:var(--text-dim);font-size:.8rem;margin-top:.5rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:1.2rem;text-align:center}}
  .stat-card .num{{font-family:var(--font-display);font-size:2.2rem;font-weight:800;color:var(--accent);display:block}}
  .stat-card .num.blue{{color:var(--accent2)}}.stat-card .num.red{{color:var(--accent3)}}.stat-card .num.yellow{{color:var(--accent4)}}
  .stat-card .label{{color:var(--text-dim);font-size:.75rem;text-transform:uppercase;letter-spacing:1px}}
  .table-wrap{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
  .table-header{{padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem}}
  .table-header h2{{font-family:var(--font-display);font-size:1rem;font-weight:700}}
  .dot{{width:8px;height:8px;border-radius:50%;background:var(--accent);display:inline-block}}
  table{{width:100%;border-collapse:collapse;font-size:.82rem}}
  thead th{{padding:.75rem 1rem;text-align:left;color:var(--text-dim);font-size:.72rem;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);background:var(--bg3)}}
  tbody tr{{border-bottom:1px solid var(--border);transition:background .15s}}
  tbody tr:last-child{{border-bottom:none}}
  tbody tr:hover{{background:var(--bg3)}}
  td{{padding:.7rem 1rem;vertical-align:middle}}
  code{{color:var(--accent2);font-size:.85rem}}
  .title-cell{{color:var(--text-dim);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
  .badge{{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.5px}}
  .badge.live{{background:rgba(0,255,157,.15);color:var(--accent);border:1px solid rgba(0,255,157,.3)}}
  .badge.dead{{background:rgba(100,116,139,.15);color:var(--text-dim);border:1px solid var(--border)}}
  .status{{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700}}
  .status.ok{{color:var(--accent)}}.status.warn{{color:var(--accent4)}}.status.err{{color:var(--accent3)}}
  .src{{padding:2px 7px;border-radius:4px;font-size:.68rem;font-weight:700;letter-spacing:.5px}}
  .src-bruteforce{{background:rgba(0,184,255,.1);color:var(--accent2);border:1px solid rgba(0,184,255,.2)}}
  .src-crtsh{{background:rgba(255,165,2,.1);color:var(--accent4);border:1px solid rgba(255,165,2,.2)}}
  .src-both{{background:rgba(0,255,157,.1);color:var(--accent);border:1px solid rgba(0,255,157,.2)}}
  .footer{{margin-top:2rem;text-align:center;color:var(--text-dim);font-size:.75rem}}
  input#search{{background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:var(--font-mono);font-size:.82rem;padding:.4rem .75rem;margin-left:auto;outline:none;width:220px}}
  input#search:focus{{border-color:var(--accent)}}
</style>
</head>
<body>
<div class="header">
  <h1>SubDomEnum <span>:: {domain}</span></h1>
  <div class="meta">Generated: {now} &nbsp;|&nbsp; Tool: SubDomEnum v1.0 &nbsp;|&nbsp; brute-force + crt.sh + live validation</div>
</div>
<div class="stats">
  <div class="stat-card"><span class="num">{stats.get('wordlist_size',0)}</span><span class="label">Words Tested</span></div>
  <div class="stat-card"><span class="num blue">{found_count}</span><span class="label">Found</span></div>
  <div class="stat-card"><span class="num">{live_count}</span><span class="label">Live</span></div>
  <div class="stat-card"><span class="num yellow">{stats.get('crtsh_count',0)}</span><span class="label">From crt.sh</span></div>
  <div class="stat-card"><span class="num red">{stats.get('duration','0')}s</span><span class="label">Duration</span></div>
</div>
<div class="table-wrap">
  <div class="table-header">
    <span class="dot"></span>
    <h2>Results — {found_count} subdomains</h2>
    <input id="search" type="text" placeholder="filter..." oninput="filterTable(this.value)">
  </div>
  <table id="results-table">
    <thead><tr><th>Subdomain</th><th>Status</th><th>HTTP Code</th><th>IP(s)</th><th>Page Title</th><th>Source</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="footer">SubDomEnum &mdash; 100 Cybersecurity Apps in 100 Days &mdash; Day 7</div>
<script>
function filterTable(q){{
  q=q.toLowerCase();
  document.querySelectorAll('#results-table tbody tr').forEach(r=>{{
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
  }});
}}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def run_enumeration(args):
    domain = args.domain.lower().strip()
    # limpiar si pasan http:// por error
    domain = re.sub(r"https?://", "", domain).strip("/")

    threads    = args.threads
    timeout    = args.timeout
    validate   = not args.no_validate
    output_json = args.json
    output_csv  = args.csv
    output_html = args.html
    wordlist_path = args.wordlist

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    start_time = time.time()

    # Banner
    console.print()
    console.print(Panel(
        Text.assemble(
            ("  ███████╗██╗   ██╗██████╗ \n", "bold green"),
            ("  ██╔════╝██║   ██║██╔══██╗\n", "bold green"),
            ("  ███████╗██║   ██║██████╔╝\n", "bold green"),
            ("  ╚════██║██║   ██║██╔══██╗\n", "bold green"),
            ("  ███████║╚██████╔╝██████╔╝\n", "bold green"),
            ("  ╚══════╝ ╚═════╝ ╚═════╝ \n", "bold green"),
            ("  SubDomEnum v1.0  ", "bold white"),
            ("— Day 7 of 100\n", "dim green"),
            ("  Subdomain Enumerator", "dim white"),
        ),
        border_style="green",
        padding=(0, 1),
    ))
    console.print()

    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    info_table.add_column("k", style="dim")
    info_table.add_column("v", style="bold cyan")
    info_table.add_row("Target", domain)
    info_table.add_row("Threads", str(threads))
    info_table.add_row("Timeout", f"{timeout}s")
    info_table.add_row("Live validation", "Yes" if validate else "No")
    info_table.add_row("Wordlist", wordlist_path or "built-in (1500+ words)")
    console.print(info_table)
    console.print()

    # Wordlist
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            console.print(f"[dim]Loaded [bold]{len(words)}[/bold] words from {wordlist_path}[/dim]")
        except FileNotFoundError:
            console.print(f"[red][!] Wordlist not found: {wordlist_path}[/red]")
            sys.exit(1)
    else:
        words = list(dict.fromkeys(BUILTIN_WORDLIST))  # deduplicate
        console.print(f"[dim]Built-in wordlist: [bold]{len(words)}[/bold] words[/dim]")

    candidates = [f"{w}.{domain}" for w in words]
    found = {}

    # ── PHASE 1: crt.sh ──
    console.print(f"\n[bold green]▶[/bold green] [bold]Phase 1:[/bold] Certificate Transparency (crt.sh)")
    with console.status("[dim]Querying crt.sh...[/dim]", spinner="dots"):
        crtsh_subs = fetch_crtsh(domain)

    if crtsh_subs:
        console.print(f"  [green]✓[/green] Found [bold]{len(crtsh_subs)}[/bold] subdomains in CT logs")
        for sub in crtsh_subs:
            if sub not in found:
                found[sub] = {"subdomain": sub, "ips": [], "source": "crtsh", "live": False}
    else:
        console.print("  [yellow]⚠[/yellow]  No CT results — puede ser que crt.sh no tenga registros para este dominio")

    # ── PHASE 2: Brute Force DNS ──
    console.print(f"\n[bold green]▶[/bold green] [bold]Phase 2:[/bold] DNS Brute Force — [bold]{len(candidates)}[/bold] candidates ({threads} threads)\n")
    brute_found = 0

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="green", complete_style="bold green"),
        TextColumn("[bold cyan]{task.completed}/{task.total}"),
        TextColumn("[bold green]{task.fields[found]} found"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("  DNS...", total=len(candidates), found=0)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in candidates}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sub = result["subdomain"]
                    ips_str = ", ".join(result["ips"][:2])
                    if sub in found:
                        found[sub]["source"] = "both"
                        found[sub]["ips"] = result["ips"]
                    else:
                        found[sub] = {**result, "live": False}
                    brute_found += 1
                    progress.update(task, advance=1, found=brute_found)
                    progress.console.print(
                        f"  [bold green]FOUND[/bold green]  [cyan]{sub:<50}[/cyan]  [dim]{ips_str}[/dim]"
                    )
                else:
                    progress.update(task, advance=1)

    console.print(f"\n  [green]✓[/green] Brute force encontró [bold]{brute_found}[/bold] subdominios")

    # ── PHASE 3: Live Validation ──
    if validate and found:
        console.print(f"\n[bold green]▶[/bold green] [bold]Phase 3:[/bold] Live Validation — [bold]{len(found)}[/bold] targets\n")
        live_count = 0

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="bold cyan"),
            TextColumn("[bold cyan]{task.completed}/{task.total}"),
            TextColumn("[bold green]{task.fields[live]} live"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("  Probing...", total=len(found), live=0)
            with ThreadPoolExecutor(max_workers=min(threads, 20)) as executor:
                futures = {executor.submit(check_live, sub, timeout): sub for sub in found}
                for future in as_completed(futures):
                    sub = futures[future]
                    live_data = future.result()
                    is_live = live_data.get("https") or live_data.get("http")
                    found[sub].update({
                        "live": bool(is_live),
                        "status_code": live_data.get("status_code"),
                        "title": live_data.get("title"),
                        "redirect": live_data.get("redirect"),
                    })
                    if is_live:
                        live_count += 1
                        code = live_data.get("status_code", "-")
                        title = (live_data.get("title") or "-")[:50]
                        code_color = "green" if str(code).startswith("2") else "yellow" if str(code).startswith("3") else "red"
                        progress.console.print(
                            f"  [bold cyan]LIVE[/bold cyan]   [cyan]{sub:<50}[/cyan]  "
                            f"[{code_color}]{code}[/{code_color}]  [dim]{title}[/dim]"
                        )
                    progress.update(task, advance=1, live=live_count)

        console.print(f"\n  [green]✓[/green] [bold]{live_count}[/bold] subdominios están vivos")
    elif not validate:
        console.print("\n[dim]Live validation skipped (--no-validate)[/dim]")

    # ── RESULTS ──
    results = sorted(found.values(), key=lambda x: (not x.get("live"), x["subdomain"]))
    duration = round(time.time() - start_time, 1)

    console.print(f"\n[bold green]▶[/bold green] [bold]Resumen final[/bold] — {len(results)} subdominios en {duration}s\n")

    if results:
        table = Table(box=box.ROUNDED, border_style="dim", header_style="bold dim", padding=(0,1))
        table.add_column("Subdomain", style="cyan", no_wrap=True, min_width=35)
        table.add_column("Live", justify="center", width=6)
        table.add_column("Code", justify="center", width=6)
        table.add_column("IP(s)", style="dim", min_width=15, no_wrap=True)
        table.add_column("Title", style="dim", min_width=30, max_width=55, no_wrap=True)
        table.add_column("Source", justify="center", width=12)

        src_colors = {"bruteforce": "blue", "crtsh": "yellow", "both": "green"}

        for r in results:
            live_icon = "[bold green]●[/bold green]" if r.get("live") else "[dim]○[/dim]"
            code = str(r.get("status_code") or "-")
            code_style = "green" if code.startswith("2") else "yellow" if code.startswith("3") else "red" if code.startswith(("4","5")) else "dim"
            ips = ", ".join(r.get("ips",[])[:2]) or "-"
            title = (r.get("title") or "-")[:55]
            src = r.get("source","bruteforce")
            table.add_row(
                r["subdomain"], live_icon,
                f"[{code_style}]{code}[/{code_style}]",
                ips, title,
                f"[{src_colors.get(src,'white')}]{src}[/{src_colors.get(src,'white')}]",
            )
        console.print(table)
    else:
        console.print("[yellow]  No se encontraron subdominios.[/yellow]")
        console.print("[dim]  Tip: probá con una wordlist más grande usando -w[/dim]")
        console.print("[dim]  Ejemplo: -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt[/dim]")

    # Stats
    live_total  = sum(1 for r in results if r.get("live"))
    crtsh_total = sum(1 for r in results if r.get("source") in ("crtsh","both"))
    brute_total = sum(1 for r in results if r.get("source") in ("bruteforce","both"))

    console.print()
    console.print(Columns([
        Panel(f"[bold cyan]{len(results)}[/bold cyan]\n[dim]total[/dim]", border_style="dim", padding=(0,2)),
        Panel(f"[bold green]{live_total}[/bold green]\n[dim]live[/dim]", border_style="dim", padding=(0,2)),
        Panel(f"[bold yellow]{crtsh_total}[/bold yellow]\n[dim]crt.sh[/dim]", border_style="dim", padding=(0,2)),
        Panel(f"[bold blue]{brute_total}[/bold blue]\n[dim]brute[/dim]", border_style="dim", padding=(0,2)),
        Panel(f"[bold red]{duration}s[/bold red]\n[dim]tiempo[/dim]", border_style="dim", padding=(0,2)),
    ], equal=True))

    # Outputs
    stats = {"wordlist_size": len(words), "crtsh_count": crtsh_total, "duration": duration}

    if output_json:
        path = output_json if output_json.endswith(".json") else output_json + ".json"
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]✓[/green] JSON → [bold]{path}[/bold]")

    if output_csv:
        path = output_csv if output_csv.endswith(".csv") else output_csv + ".csv"
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["subdomain","live","status_code","ips","title","source","redirect"])
            writer.writeheader()
            for r in results:
                row = dict(r)
                row["ips"] = ", ".join(r.get("ips",[]))
                writer.writerow(row)
        console.print(f"[green]✓[/green] CSV → [bold]{path}[/bold]")

    if output_html:
        path = output_html if output_html.endswith(".html") else output_html + ".html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(generate_html_report(domain, results, stats))
        console.print(f"[green]✓[/green] HTML → [bold]{path}[/bold]")

    console.print()


def main():
    parser = argparse.ArgumentParser(
        prog="SubDomEnum",
        description="Subdomain Enumerator — brute force + crt.sh + live validation",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos:
  python SubDomEnum.py vulnweb.com
  python SubDomEnum.py vulnweb.com --html reporte
  python SubDomEnum.py vulnweb.com -w wordlist.txt --json resultados
  python SubDomEnum.py vulnweb.com -t 100 --no-validate
        """,
    )
    parser.add_argument("domain", help="Dominio objetivo (ej: vulnweb.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist externa (opcional)", default=None)
    parser.add_argument("-t", "--threads", help="Threads (default: 50)", type=int, default=50)
    parser.add_argument("--timeout", help="Timeout HTTP en segundos (default: 5)", type=int, default=5)
    parser.add_argument("--no-validate", help="Saltar validación HTTP/HTTPS", action="store_true")
    parser.add_argument("--json", help="Guardar resultados en JSON", metavar="FILE", default=None)
    parser.add_argument("--csv", help="Guardar resultados en CSV", metavar="FILE", default=None)
    parser.add_argument("--html", help="Generar reporte HTML", metavar="FILE", default=None)

    args = parser.parse_args()
    run_enumeration(args)


if __name__ == "__main__":
    main()