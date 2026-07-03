"""DNS lookup and trace logic, built directly on dnspython (no dig binary)."""

import concurrent.futures
import ipaddress
import re
import socket
import time

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename

RECORD_TYPES = {
    "A", "AAAA", "ANY", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NS",
    "PTR", "SOA", "SRV", "TLSA", "TSIG", "TXT",
}

# IPv4 addresses of the 13 DNS root servers (root hints).
ROOT_HINTS = [
    ("a.root-servers.net.", "198.41.0.4"),
    ("b.root-servers.net.", "199.9.14.201"),
    ("c.root-servers.net.", "192.33.4.12"),
    ("d.root-servers.net.", "199.7.91.13"),
    ("e.root-servers.net.", "192.203.230.10"),
    ("f.root-servers.net.", "192.5.5.241"),
    ("g.root-servers.net.", "192.112.36.4"),
    ("h.root-servers.net.", "198.97.190.53"),
    ("i.root-servers.net.", "192.36.148.17"),
    ("j.root-servers.net.", "192.58.128.30"),
    ("k.root-servers.net.", "193.0.14.129"),
    ("l.root-servers.net.", "199.7.83.42"),
    ("m.root-servers.net.", "202.12.27.33"),
]

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$"
)


class DigError(Exception):
    """Raised for operational DNS failures (timeout, unreachable server, etc)."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


class InvalidInputError(Exception):
    """Raised for bad user input (domain, record type, server IP)."""


def validate_domain(domain, rdtype="A"):
    domain = (domain or "").strip()
    if not domain:
        raise InvalidInputError("Domain is required.")

    if rdtype == "PTR":
        try:
            addr = ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            return dns.reversename.from_address(str(addr)).to_text()

    if not _HOSTNAME_RE.match(domain):
        raise InvalidInputError(f"'{domain}' is not a valid domain name.")
    return domain


def validate_server(server):
    if not server:
        return None
    try:
        ipaddress.ip_address(server)
    except ValueError:
        raise InvalidInputError(f"'{server}' is not a valid IP address.")
    return server


def validate_rdtype(rdtype):
    rdtype = (rdtype or "A").strip().upper()
    if rdtype not in RECORD_TYPES:
        raise InvalidInputError(f"'{rdtype}' is not a supported record type.")
    return rdtype


def _rrset_to_answers(rrset):
    if rrset is None:
        return []
    return [
        {
            "name": rrset.name.to_text(),
            "ttl": rrset.ttl,
            "type": dns.rdatatype.to_text(rrset.rdtype),
            "data": rdata.to_text(),
        }
        for rdata in rrset
    ]


def lookup(domain, rdtype="A", server=None, timeout=5.0, short=False):
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    query_info = {"domain": domain, "type": rdtype, "server": server}

    # ANY and other metaquery types are rejected by dnspython's high-level
    # resolver, so query the recursive nameserver directly, the way dig does.
    if dns.rdatatype.is_metatype(dns.rdatatype.from_text(rdtype)):
        return _metaquery_lookup(domain, rdtype, server, timeout, short, query_info)

    try:
        start = time.monotonic()
        answer = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        elapsed_ms = (time.monotonic() - start) * 1000
    except dns.resolver.NXDOMAIN:
        return {
            "query": query_info,
            "rcode": "NXDOMAIN",
            "flags": "",
            "authoritative": False,
            "query_time_ms": None,
            "answers": [],
        }
    except dns.exception.Timeout:
        raise DigError("DNS query timed out.", "timeout")
    except dns.resolver.NoNameservers as exc:
        raise DigError(f"No response from nameserver: {exc}", "no_nameservers")

    response = answer.response
    rcode = dns.rcode.to_text(response.rcode())
    flags = dns.flags.to_text(response.flags)
    authoritative = bool(response.flags & dns.flags.AA)
    answers = _rrset_to_answers(answer.rrset)

    if short:
        return {
            "query": query_info,
            "query_time_ms": round(elapsed_ms, 1),
            "answers": [a["data"] for a in answers],
        }

    # Best-effort: also report the TTL as configured at the authoritative
    # server, since the TTL above may already be decremented if it came from
    # a caching resolver. Skipped if the answer was already authoritative
    # (nothing to compare against) or the record type has no single TTL.
    if answers and rdtype != "ANY" and not authoritative:
        full_ttl = _authoritative_ttl(domain, dns.rdatatype.from_text(rdtype))
        if full_ttl is not None:
            for a in answers:
                a["full_ttl"] = full_ttl

    result = {
        "query": query_info,
        "rcode": rcode,
        "flags": flags,
        "authoritative": authoritative,
        "query_time_ms": round(elapsed_ms, 1),
        "answers": answers,
    }

    # Bake in provider fingerprinting for MX/NS lookups, so the normal dig
    # flow for those two record types shows "Google Workspace"/"Cloudflare"/
    # etc. without a separate report.
    if answers and rdtype in _PROVIDER_PATTERNS:
        patterns, default_label = _PROVIDER_PATTERNS[rdtype]
        joined = " ".join(a["data"] for a in answers).lower()
        result["provider"] = next(
            (label for pattern, label in patterns if pattern.search(joined)), default_label
        )

    return result


def _metaquery_lookup(domain, rdtype, server, timeout, short, query_info):
    """Direct recursive query for metaquery types (e.g. ANY) that the
    high-level resolver refuses. Sends RD=1 to the configured/system
    nameserver, falling back to TCP on truncation."""
    if server is None:
        system = dns.resolver.Resolver()
        if not system.nameservers:
            raise DigError("No nameserver configured to query.", "no_nameservers")
        server = system.nameservers[0]

    qname = dns.name.from_text(domain)
    q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))

    try:
        start = time.monotonic()
        response = dns.query.udp(q, server, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(q, server, timeout=timeout)
        elapsed_ms = (time.monotonic() - start) * 1000
    except dns.exception.Timeout:
        raise DigError("DNS query timed out.", "timeout")

    answers = []
    for rrset in response.answer:
        answers.extend(_rrset_to_answers(rrset))

    if short:
        return {
            "query": query_info,
            "query_time_ms": round(elapsed_ms, 1),
            "answers": [a["data"] for a in answers],
        }

    return {
        "query": query_info,
        "rcode": dns.rcode.to_text(response.rcode()),
        "flags": dns.flags.to_text(response.flags),
        "authoritative": bool(response.flags & dns.flags.AA),
        "query_time_ms": round(elapsed_ms, 1),
        "answers": answers,
    }


def _send_query(qname, rdtype_obj, server_ip, timeout):
    q = dns.message.make_query(qname, rdtype_obj)
    q.flags &= ~dns.flags.RD
    response = dns.query.udp(q, server_ip, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(q, server_ip, timeout=timeout)
    return response


def _glue_for(ns_names, additional):
    """Return list of (ns_name, ip) pairs found in the additional section, IPv4 first."""
    glue = {"A": {}, "AAAA": {}}
    for rrset in additional:
        type_text = dns.rdatatype.to_text(rrset.rdtype)
        if type_text in glue:
            name = rrset.name.to_text()
            glue[type_text][name] = [rdata.to_text() for rdata in rrset]

    servers = []
    for ns_name in ns_names:
        if ns_name in glue["A"]:
            servers.append((ns_name, glue["A"][ns_name][0]))
        elif ns_name in glue["AAAA"]:
            servers.append((ns_name, glue["AAAA"][ns_name][0]))
    return servers


def _record_hop(hops, server_name, server_ip, hop_ms, authoritative, rcode, **extra):
    """Append a hop to the trail. All hops share the same header fields; the
    variant payload (answers / cname / referral) is passed via **extra."""
    hops.append({
        "step": len(hops) + 1,
        "server": server_ip,
        "server_name": server_name,
        "query_time_ms": round(hop_ms, 1),
        "authoritative": authoritative,
        "rcode": rcode,
        **extra,
    })


def _iterative_resolve(qname, rdtype_obj, timeout=3.0, max_hops=30, budget=20.0):
    """Iteratively resolve qname/rdtype starting from the root hints,
    following referrals and CNAME redirects, exactly like `dig +trace`.

    Returns (hops, final_answer, error). `final_answer` is
    {"authoritative": bool, "answers": [...]} or None if resolution
    didn't complete.
    """
    current_servers = list(ROOT_HINTS)
    hops = []
    seen = set()
    final_answer = None
    error = None

    start = time.monotonic()

    while len(hops) < max_hops and (time.monotonic() - start) < budget:
        response = None
        used_server = None
        for server_name, server_ip in current_servers:
            key = (server_ip, qname.to_text(), rdtype_obj)
            if key in seen:
                continue
            try:
                hop_start = time.monotonic()
                response = _send_query(qname, rdtype_obj, server_ip, timeout)
                hop_ms = (time.monotonic() - hop_start) * 1000
                used_server = (server_name, server_ip)
                seen.add(key)
                break
            except (dns.exception.Timeout, OSError):
                continue

        if response is None:
            error = "No reachable nameserver could be queried for this hop."
            break

        rcode = dns.rcode.to_text(response.rcode())
        is_authoritative = bool(response.flags & dns.flags.AA)
        server_name, server_ip = used_server

        if rcode in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
            _record_hop(hops, server_name, server_ip, hop_ms, is_authoritative, rcode)
            error = f"Received {rcode} from {server_name} ({server_ip})."
            break

        matching = [
            rrset for rrset in response.answer
            if rrset.rdtype == rdtype_obj and rrset.name == qname
        ]
        cname_rrset = next(
            (rrset for rrset in response.answer if rrset.rdtype == dns.rdatatype.CNAME),
            None,
        )

        if matching:
            answers = []
            for rrset in matching:
                answers.extend(_rrset_to_answers(rrset))
            _record_hop(hops, server_name, server_ip, hop_ms, is_authoritative, rcode, answers=answers)
            final_answer = {"authoritative": is_authoritative, "answers": answers}
            break

        if cname_rrset and rdtype_obj != dns.rdatatype.CNAME:
            target = cname_rrset[0].target
            _record_hop(hops, server_name, server_ip, hop_ms, is_authoritative, rcode,
                        cname=target.to_text())
            qname = target
            current_servers = list(ROOT_HINTS)
            continue

        ns_rrsets = [rrset for rrset in response.authority if rrset.rdtype == dns.rdatatype.NS]
        if not ns_rrsets:
            _record_hop(hops, server_name, server_ip, hop_ms, is_authoritative, rcode, answers=[])
            final_answer = {"authoritative": is_authoritative, "answers": []}
            break

        ns_names = [rdata.target.to_text() for rrset in ns_rrsets for rdata in rrset]
        next_servers = _glue_for(ns_names, response.additional)

        referral = [{"ns": name, "glue": ip} for name, ip in next_servers] if next_servers else [
            {"ns": name, "glue": None} for name in ns_names
        ]

        _record_hop(hops, server_name, server_ip, hop_ms, is_authoritative, rcode, referral=referral)

        if not next_servers:
            # Glueless delegation: resolve one NS name via the system resolver.
            for ns_name in ns_names:
                try:
                    resolved = dns.resolver.resolve(ns_name, "A", lifetime=timeout)
                    next_servers = [(ns_name, resolved[0].to_text())]
                    break
                except dns.exception.DNSException:
                    continue

        if not next_servers:
            error = "Could not resolve any nameserver for the next hop (glueless delegation)."
            break

        current_servers = next_servers

    return hops, final_answer, error


def _authoritative_ttl(domain, rdtype_obj, timeout=1.5, max_hops=15, budget=4.0):
    """Best-effort: resolve straight to the authoritative server (bypassing
    any caching resolver) and return the TTL as configured in the zone.
    Returns None if it can't be determined within the time/hop budget.
    """
    qname = dns.name.from_text(domain)
    try:
        _, final_answer, error = _iterative_resolve(
            qname, rdtype_obj, timeout=timeout, max_hops=max_hops, budget=budget
        )
    except Exception:
        return None
    if error or not final_answer or not final_answer["answers"]:
        return None
    return final_answer["answers"][0]["ttl"]


def trace(domain, rdtype="A", timeout=3.0, max_hops=30):
    qname = dns.name.from_text(domain)
    rdtype_obj = dns.rdatatype.from_text(rdtype)
    query_info = {"domain": domain, "type": rdtype}

    start = time.monotonic()
    hops, final_answer, error = _iterative_resolve(qname, rdtype_obj, timeout=timeout, max_hops=max_hops)
    total_ms = (time.monotonic() - start) * 1000

    return {
        "query": query_info,
        "hops": hops,
        "final_answer": final_answer,
        "total_time_ms": round(total_ms, 1),
        "error": error,
    }


def _resolve_txt_strings(resolver, name):
    try:
        answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except dns.exception.DNSException:
        return []
    if answer.rrset is None:
        return []
    return [
        b"".join(rdata.strings).decode("utf-8", "replace")
        for rdata in answer.rrset
    ]


def _check_spf(domain, resolver):
    for txt in _resolve_txt_strings(resolver, domain):
        if txt.lower().startswith("v=spf1"):
            if "-all" in txt:
                policy = "hardfail"
            elif "~all" in txt:
                policy = "softfail"
            elif "?all" in txt:
                policy = "neutral"
            elif "+all" in txt:
                policy = "allow_all"
            else:
                policy = "unknown"
            return {"present": True, "record": txt, "policy": policy}
    return {"present": False, "record": None, "policy": None}


def _check_dmarc(domain, resolver):
    for txt in _resolve_txt_strings(resolver, f"_dmarc.{domain}"):
        if txt.lower().startswith("v=dmarc1"):
            policy_match = re.search(r"p=(none|quarantine|reject)", txt, re.I)
            rua_match = re.search(r"rua=([^;]+)", txt, re.I)
            return {
                "present": True,
                "record": txt,
                "policy": policy_match.group(1).lower() if policy_match else None,
                "rua": rua_match.group(1).strip() if rua_match else None,
            }
    return {"present": False, "record": None, "policy": None, "rua": None}


DKIM_SELECTORS = [
    "google", "google2", "k1", "k2", "s1", "s2", "default", "mail", "dkim",
    "selector1", "selector2", "smtp", "hubspot", "s1024", "everlytickey1", "k3",
]


def _check_dkim(domain, resolver):
    def probe(selector):
        name = f"{selector}._domainkey.{domain}"
        try:
            answer = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.exception.DNSException:
            return None
        if answer.rrset is None:
            return None
        for rdata in answer.rrset:
            txt = b"".join(rdata.strings).decode("utf-8", "replace")
            if "v=dkim1" in txt.lower():
                records = []
                # If the resolver followed a CNAME, fetch and prepend it.
                if answer.canonical_name.to_text() != dns.name.from_text(name).to_text():
                    try:
                        cname_answer = resolver.resolve(name, "CNAME", raise_on_no_answer=False)
                        if cname_answer.rrset is not None:
                            records.append({
                                "name": cname_answer.rrset.name.to_text(),
                                "ttl": cname_answer.rrset.ttl,
                                "type": "CNAME",
                                "data": cname_answer.rrset[0].target.to_text(),
                            })
                    except dns.exception.DNSException:
                        pass
                records.append({
                    "name": answer.rrset.name.to_text(),
                    "ttl": answer.rrset.ttl,
                    "type": "TXT",
                    "data": txt,
                })
                return {"selector": selector, "records": records}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = [r for r in pool.map(probe, DKIM_SELECTORS) if r]

    return {
        "selectors_checked": len(DKIM_SELECTORS),
        "selectors_found": [r["selector"] for r in results],
        "records": [rec for r in results for rec in r["records"]],
    }


MX_PROVIDER_PATTERNS = [
    (re.compile(r"google|googlemail|aspmx", re.I), "Google Workspace"),
    (re.compile(r"outlook|hotmail|protection\.outlook|mail\.protection", re.I),
     "Microsoft 365 / Exchange Online"),
    (re.compile(r"mimecast", re.I), "Mimecast (gateway — check upstream MX)"),
    (re.compile(r"proofpoint|pphosted|ppe-hosted", re.I), "Proofpoint (gateway — check upstream MX)"),
    (re.compile(r"barracuda", re.I), "Barracuda (gateway — check upstream MX)"),
    (re.compile(r"zoho", re.I), "Zoho Mail"),
    (re.compile(r"amazonses|aws", re.I), "Amazon SES"),
    (re.compile(r"arsmtp", re.I), "AppRiver"),
    (re.compile(r"fastmail", re.I), "Fastmail"),
]


NS_PROVIDER_PATTERNS = [
    (re.compile(r"awsdns", re.I), "Amazon Route 53"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"google", re.I), "Google Cloud DNS"),
    (re.compile(r"azure-dns", re.I), "Azure DNS"),
    (re.compile(r"godaddy|domaincontrol", re.I), "GoDaddy"),
    (re.compile(r"namecheap", re.I), "Namecheap"),
    (re.compile(r"squarespace", re.I), "Squarespace"),
    (re.compile(r"wpengine", re.I), "WP Engine"),
]

_PROVIDER_PATTERNS = {
    "MX": (MX_PROVIDER_PATTERNS, "Unknown / Self-hosted"),
    "NS": (NS_PROVIDER_PATTERNS, "Unknown / Custom"),
}


IANA_WHOIS = "whois.iana.org"

WHOIS_FIELD_LABELS = [
    "Registrar",
    "Registrar URL",
    "Creation Date",
    "Updated Date",
    "Registry Expiry Date",
    "Registrant Organization",
    "Registrant Country",
]


def _whois_query(server, query, timeout):
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _parse_whois_fields(text):
    fields = {}
    for label in WHOIS_FIELD_LABELS:
        match = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", text, re.I | re.M)
        if match:
            fields[label] = match.group(1).strip()
    return fields


def _check_whois(domain, timeout=5.0):
    """Best-effort registrar/registration lookup via the raw WHOIS protocol
    (port 43): ask IANA which server is authoritative for the TLD, query it,
    then follow one "Registrar WHOIS Server:" referral for the full record.
    """
    result = {"present": False, "privacy_protected": False}
    try:
        tld = domain.rstrip(".").rsplit(".", 1)[-1]
        iana_response = _whois_query(IANA_WHOIS, tld, timeout)
        referral = re.search(r"^\s*whois:\s*(\S+)", iana_response, re.I | re.M)
        if not referral:
            return result
        server = referral.group(1)

        text = _whois_query(server, domain, timeout)
        fields = _parse_whois_fields(text)

        registrar_referral = re.search(r"^\s*Registrar WHOIS Server:\s*(\S+)", text, re.I | re.M)
        if registrar_referral and registrar_referral.group(1).lower() != server.lower():
            registrar_text = _whois_query(registrar_referral.group(1), domain, timeout)
            fields.update(_parse_whois_fields(registrar_text))
            text += "\n" + registrar_text

        if not fields:
            return result

        result.update({
            "present": True,
            "registrar": fields.get("Registrar"),
            "registrar_url": fields.get("Registrar URL"),
            "created": fields.get("Creation Date"),
            "updated": fields.get("Updated Date"),
            "expires": fields.get("Registry Expiry Date"),
            "registrant_org": fields.get("Registrant Organization"),
            "registrant_country": fields.get("Registrant Country"),
            "privacy_protected": bool(re.search(r"privacy|redacted|protected|withheld", text, re.I)),
        })
        return result
    except Exception:
        return result


def _resolver(timeout=3.0):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def check_registrar(domain, timeout=5.0):
    return _check_whois(domain, timeout)


def check_spf(domain, timeout=3.0):
    return _check_spf(domain, _resolver(timeout))


def check_dmarc(domain, timeout=3.0):
    return _check_dmarc(domain, _resolver(timeout))


def check_dkim(domain, timeout=3.0):
    return _check_dkim(domain, _resolver(timeout))
