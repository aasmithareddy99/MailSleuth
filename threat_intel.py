"""Opt-in indicator enrichment. Never uploads full email bodies."""
from __future__ import annotations
import os, socket, ipaddress, json, urllib.parse, urllib.request, urllib.error
from urllib.parse import urlparse

TIMEOUT = 2.5

def domain_dns(domain: str) -> dict:
    if not domain or len(domain) > 253 or any(c in domain for c in '/:@ '):
        return {'status':'skipped','reason':'No valid sender domain'}
    domain = domain.strip('.').lower()
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        addresses = set()
        for record_type in ('A', 'AAAA'):
            try:
                answers = resolver.resolve(domain, record_type, lifetime=TIMEOUT)
                addresses.update(str(item) for item in answers)
            except Exception:
                pass
        if not addresses:
            return {'status':'no_resolution','domain':domain,'reason':'No A/AAAA answer or DNS lookup failed'}
        records = sorted(addresses)
        return {'status':'resolved','domain':domain,'addresses':[{'ip':ip,'scope':'public' if ipaddress.ip_address(ip).is_global else 'private/reserved'} for ip in records[:20]]}
    except ImportError:
        # Fallback is bounded by platform resolver behavior; dnspython is recommended.
        try:
            records = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)})
            return {'status':'resolved','domain':domain,'addresses':[{'ip':ip,'scope':'public' if ipaddress.ip_address(ip).is_global else 'private/reserved'} for ip in records[:20]],'note':'Install dnspython for bounded DNS timeouts.'}
        except (socket.gaierror, TimeoutError, OSError) as exc:
            return {'status':'no_resolution','domain':domain,'reason':type(exc).__name__}
    except Exception as exc:
        return {'status':'no_resolution','domain':domain,'reason':type(exc).__name__}

def urlhaus_host_lookup(domain: str) -> dict:
    """Optional URLhaus host lookup; only domain is sent, never message content. Requires explicit opt-in and key."""
    key = os.getenv('URLHAUS_AUTH_KEY','').strip()
    if not key:
        return {'status':'not_configured','provider':'URLhaus','reason':'Set URLHAUS_AUTH_KEY to enable reputation lookups.'}
    if not domain or len(domain)>253 or any(c in domain for c in '/:@ '):
        return {'status':'skipped','provider':'URLhaus','reason':'Invalid domain'}
    data = urllib.parse.urlencode({'host':domain}).encode()
    req = urllib.request.Request('https://urlhaus-api.abuse.ch/v1/host/', data=data,
        headers={'Auth-Key':key,'User-Agent':'MailSleuth-SIH-Prototype/1.0','Content-Type':'application/x-www-form-urlencoded'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            payload = json.loads(response.read(256_000).decode('utf-8','replace'))
        status = payload.get('query_status','unknown')
        urls = payload.get('urls',[]) if isinstance(payload.get('urls',[]),list) else []
        return {'status':status,'provider':'URLhaus','host':domain,'match_count':len(urls),'alerts':[{'url_status':x.get('url_status'),'threat':x.get('threat'),'date_added':x.get('date_added')} for x in urls[:10]]}
    except Exception as exc:
        return {'status':'error','provider':'URLhaus','reason':type(exc).__name__}

def enrich_indicators(domain: str, urls: list[str]) -> dict:
    # Explicit request-level opt-in is required by the caller. Only domains are sent to the provider.
    dns = domain_dns(domain)
    candidates = []
    ip_literals = []
    for value in urls[:20]:
        parsed = urlparse(value if value.lower().startswith(('http://','https://')) else 'http://' + value)
        host = (parsed.hostname or '').strip('.').lower()
        if not host:
            continue
        try:
            parsed_ip = ipaddress.ip_address(host)
            ip_literals.append({'url_host':host,'scope':'public' if parsed_ip.is_global else 'private/reserved'})
            # Public/private IP literals are classified locally; do not submit IPs as domain names.
            continue
        except ValueError:
            pass
        if host != domain and host not in candidates and len(host) <= 253:
            candidates.append(host)
    lookups = []
    if domain:
        lookups.append({'domain':domain,'purpose':'sender domain','dns':dns,'reputation':urlhaus_host_lookup(domain)})
    for host in candidates[:5]:
        lookups.append({'domain':host,'purpose':'linked URL host','dns':domain_dns(host),'reputation':urlhaus_host_lookup(host)})
    alerts = []
    for item in lookups:
        for alert in item['reputation'].get('alerts',[]) if isinstance(item.get('reputation'),dict) else []:
            alerts.append({'domain':item['domain'],**alert})
    errors = []
    for item in lookups:
        if item['dns'].get('status') in ('error','no_resolution'):
            errors.append({'domain':item['domain'],'source':'dns','status':item['dns'].get('status')})
        if item['reputation'].get('status') == 'error':
            errors.append({'domain':item['domain'],'source':'reputation','status':'error'})
    return {'enabled':True,
        'privacy_note':'Only sender/linked URL hostnames are queried; email body and full URLs are not sent to the reputation provider. DNS queries reveal hostnames to the configured resolver.',
        'sender_domain':domain,'lookups':lookups,'alerts':alerts,'errors':errors,'url_ip_literals':ip_literals,
        'ip_enrichment_note':'IP literals in relay headers are classified locally as public or private/reserved; no geolocation is inferred.'}
