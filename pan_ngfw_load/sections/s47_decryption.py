"""TLS and decryption: the SSL proxy - what it decrypts, how many sessions at once against the model's limit,
what went wrong (resources, certificates, unsupported TLS), TLS versions and ciphers. The standard report only
gets the findings; the pages are in the extended report."""

import re

import numpy as np
import pandas as pd

from .. import capacity as CAP
from .. import charts as C

TITLE = "TLS and Decryption"
DP_SCOPED = "partly"  # chassis: the time series come from one DP (see dataset.select_dp)

PEAK_NOTICE, PEAK_WARN = 70, 90  # % of the model's decryption session limit
RES_WARN = 100  # sessions not decrypted for lack of resources: notice below, warning from here
TAILDROP_NOTICE = 1000
LEGACY_NOTICE = 1.0  # % of client-side handshakes with TLS 1.0/1.1/SSL 3.0

# what happens to the TLS sessions the proxy checks (proxy_acc_convert_to_<x>, share of proxy_process_accumulation)
FATE = {"forward_proxy": "decrypted (forward proxy)", "inbound_proxy": "decrypted (inbound inspection)",
        "nodecrypt_proxy": "no-decrypt rule (checked, not decrypted)", "no_proxy": "no decryption rule matched"}

# problem counters since boot, by area (only those above zero are listed)
THEMES = [
    ("Out of resources", r"^proxy_ssl_no_resource$|^proxy_tls13_downgrade_no_ossl_resource$|^proxy_tunnel_taildrop$|"
                         r"no_resource|alloc_fail"),
    ("Certificates", r"^proxy_ssl_(invalid|untrusted|expired)_cert$|^proxy_client_cert_parse_error$|"
                     r"^proxy_exclude_add_ssl_client_cert$|^ssl_cert_cache_miss$"),
    ("Unsupported or unreadable TLS", r"^proxy_ssl_unsupported(_cipher)?$|^proxy_client_hello_failed$|"
                                      r"^ssl_partial_client_hello_incomplete$|^ssl_unsupported_server_extension$|"
                                      r"^ssl_ossl_cipher_set_fail$"),
    ("TLS 1.3", r"^ssl_tls13_connection_error$|^proxy_tls13_downgrade_server_tls12$|^proxy_tls13_server_timedout$"),
    ("Bypassed / excluded", r"^proxy_exclude_by_(sni|cache)$|^proxy_exclude_add$"),
    ("URL category lookup", r"^proxy_url_request_(pkt_drop|timeout)$|^proxy_url_category_unknown$"),
]
RESOURCE = ["proxy_ssl_no_resource", "proxy_tls13_downgrade_no_ossl_resource"]
TIME_PROBLEMS = RESOURCE + ["proxy_tunnel_taildrop", "ssl_tls13_connection_error"]

# failure counters for the episode table: label
FAIL = {
    "proxy_ssl_no_resource": "not decrypted - no proxy resources",
    "proxy_tls13_downgrade_no_ossl_resource": "TLS 1.3 not proxied - no resources",
    "proxy_tunnel_taildrop": "packets dropped - proxy queue full",
    "ssl_tls13_connection_error": "TLS 1.3 connection errors",
    "proxy_tls13_server_timedout": "TLS 1.3 server did not answer",
    "proxy_ssl_untrusted_cert": "untrusted server certificate",
    "proxy_ssl_expired_cert": "expired server certificate",
    "proxy_ssl_invalid_cert": "invalid server certificate",
    "proxy_ssl_unsupported": "unsupported TLS version",
    "proxy_ssl_unsupported_cipher": "unsupported cipher",
    "proxy_client_hello_failed": "unreadable client hello",
    "ssl_ossl_cipher_set_fail": "cipher could not be applied",
    "proxy_url_request_pkt_drop": "packets dropped - waiting for URL category",
    "proxy_url_request_timeout": "URL category lookup timed out",
}
# an interval counts when a counter has at least this many events and EPISODE_FACTOR x its usual level (median of
# all intervals); packet counters need more than session counters
EPISODE_MIN = {"proxy_tunnel_taildrop": 1000, "proxy_url_request_pkt_drop": 100}
EPISODE_MIN_SESSIONS = 50
EPISODE_FACTOR = 5
COMMIT_BEFORE = pd.Timedelta(minutes=30)  # configuration commits this long before an episode are named

EXCLUDE_REASON = {
    "TLS13_UNSUPPORTED": "TLS 1.3 could not be proxied (e.g. no resources, unsupported extension)",
    "SSL_EXCLUSION_LIST_MATCH": "server on the decryption exclusion list",
    "SSL_UNSUPPORTED": "unsupported TLS version or cipher",
    "SSL_CLIENT_CERT": "client certificate authentication (mutual TLS)",
    "SSL_PINNED_CERT": "certificate pinning",
}


def _cipher_class(name: str) -> str:
    n = name.upper()
    if n.startswith("TLS13"):
        return "TLS 1.3 suites"
    if re.search(r"3DES|RC4|NULL|EXPORT|_DES_", n):
        return "weak (3DES / RC4 / NULL)"
    if n.startswith("TLS_RSA_"):
        return "RSA key exchange - no forward secrecy"
    if re.search(r"_E?C?DHE_", n):
        return "forward secrecy, " + ("CBC (older)" if "CBC" in n else "AEAD (GCM / ChaCha20)")
    return "other"


def _span(series: pd.Series) -> str:
    """'22.04. 14:17-14:57' for the intervals in which a rate was above zero."""
    s = series[series > 0]
    if s.empty:
        return ""
    a, b = s.index.min(), s.index.max()
    return f"{a:%d.%m. %H:%M}" + ("" if a == b else f"-{b:%H:%M}" if a.date() == b.date() else f" - {b:%d.%m. %H:%M}")


def build(ctx):
    ds = ctx.ds
    c = ds["counters_boot"].set_index("name") if ds.has("counters_boot") else pd.DataFrame(columns=["value"])
    val = lambda n: float(c.value.get(n, 0) or 0) if "value" in c else 0.0
    st = ds.meta.get("decrypt") or {}
    su = ds["scale_used"].set_index("metric") if ds.has("scale_used") else pd.DataFrame(columns=["used"])
    rules = int(su.used.get("decryption_rules", 0) or 0) if "used" in su else 0
    acc = {k: val(f"proxy_acc_convert_to_{k}") for k in FATE}
    acc_total = val("proxy_process_accumulation")
    decrypting = (rules > 0 and (st.get("forward_ready") == "yes" or st.get("inbound_ready") == "yes")) \
        or acc["forward_proxy"] > 0 or acc["inbound_proxy"] > 0 or val("proxy_sessions_forward") > 0
    tls = ds["tls_stats"] if ds.has("tls_stats") else pd.DataFrame(columns=["kind", "name", "side", "count"])
    proxied = val("proxy_process") > 0 or tls["count"].sum() > 0
    if not decrypting and not proxied:
        return []
    full = ctx.settings.get("report_kind") != "standard"  # the standard report gets the findings only
    more = "" if full else " Details: extended report (-x)."  # on the first decryption finding only
    model = ds.meta.get("model", "?")
    lim, _notes, _src, _status = CAP.limits(ctx.settings, model)
    lim_sess, lim_cache = lim.get("ssl_decrypt_sessions"), lim.get("other:ssl_decryption_ssl_certificate_cache")

    # time series (one DP on chassis models)
    dc = ds["dpm_counters"] if ds.has("dpm_counters") else pd.DataFrame(columns=["ts", "name", "value"])
    # PAN-OS lists a counter only while it is above zero - a missing sample is 0
    gauge = dc[dc.name.isin(["proxy_sessions_forward", "proxy_sessions"])].pivot_table(
        index="ts", columns="name", values="value", aggfunc="last").sort_index().fillna(0)
    rates = ds["dp_counter_rates"] if ds.has("dp_counter_rates") else pd.DataFrame(columns=["ts", "name", "rate"])
    prob = rates[rates.name.isin(TIME_PROBLEMS)].pivot_table(index="ts", columns="name", values="rate").sort_index()
    fwd = gauge.proxy_sessions_forward if "proxy_sessions_forward" in gauge else pd.Series(dtype=float)
    peak = fwd.max() if len(fwd) else np.nan
    peak_ts = fwd.idxmax() if len(fwd) else None

    # --- findings (standard and extended) ---------------------------------------------------------------
    if not decrypting:
        ctx.find("info", "Decryption", f"No decryption configured; the SSL proxy handled {val('proxy_process'):,.0f} "
                                       "TLS sessions that the firewall terminates itself (e.g. GlobalProtect)."
                 + more, whole=True)
    else:
        kinds = [k for k, v in (("forward proxy", st.get("forward_ready")),
                                ("inbound inspection", st.get("inbound_ready"))) if v == "yes"]
        txt = f"Decryption active ({' and '.join(kinds) or 'proxy'}, {rules} rule{'s' if rules != 1 else ''})"
        if acc_total:
            dec = (acc["forward_proxy"] + acc["inbound_proxy"]) / acc_total * 100
            txt += (f": {dec:.0f}% of the {acc_total:,.0f} TLS sessions checked since boot were decrypted, "
                    f"{acc['nodecrypt_proxy'] / acc_total * 100:.0f}% matched a no-decrypt rule")
        if pd.notna(peak):
            txt += f"; at most {peak:,.0f} decrypted sessions at the same time" + (
                f" ({peak / lim_sess * 100:.0f}% of the {model}'s {lim_sess:,.0f})" if lim_sess else "")
        ctx.find("info", "Decryption", txt + "." + more)
        if lim_sess and pd.notna(peak) and peak / lim_sess * 100 >= PEAK_NOTICE:
            ctx.find("warning" if peak / lim_sess * 100 >= PEAK_WARN else "notice", "Decryption",
                     f"Decrypted sessions reached {peak:,.0f} ({peak / lim_sess * 100:.0f}% of the {model}'s limit of "
                     f"{lim_sess:,.0f}) at {peak_ts:%d.%m. %H:%M}." + more)
    no_res, tls13_res = val("proxy_ssl_no_resource"), val("proxy_tls13_downgrade_no_ossl_resource")
    if no_res or tls13_res:
        when = _span(prob[[k for k in RESOURCE if k in prob]].sum(axis=1)) if len(prob) else ""
        win = _window(ds)
        parts = ([f"{no_res:,.0f} sessions not decrypted"] if no_res else []) + \
                ([f"{tls13_res:,.0f} TLS 1.3 handshakes not proxied as TLS 1.3"] if tls13_res else [])
        ctx.find("warning" if no_res + tls13_res >= RES_WARN else "notice", "Decryption",
                 "Out of proxy resources since boot: " + " and ".join(parts)
                 + (f" (in the {win}: {when})" if when else "") + "." + more, whole=not when)
    if val("proxy_tunnel_taildrop") >= TAILDROP_NOTICE:
        ctx.find("notice", "Decryption", f"{val('proxy_tunnel_taildrop'):,.0f} packets dropped because the SSL proxy's "
                                         "send queue was full (since boot)." + more, whole=True)
    entries = st.get("cert_cache_entries")
    if decrypting and entries and lim_cache and entries >= lim_cache * 0.95:
        ctx.find("notice", "Decryption", f"Certificate cache full: {entries:,.0f} of {lim_cache:,.0f} entries - the "
                                         "firewall keeps generating certificates again "
                                         f"({val('ssl_cert_cache_miss'):,.0f} cache misses since boot)." + more,
                 whole=True)
    ver = tls[(tls.kind == "version") & (tls.side == "client")].set_index("name")["count"]
    legacy = ver[ver.index.str.match(r"^(SSL|TLS1\.[01])")].sum()
    if decrypting and ver.sum() and legacy / ver.sum() * 100 >= LEGACY_NOTICE:
        ctx.find("notice", "Decryption", f"{legacy / ver.sum() * 100:.1f}% of the decrypted client connections use "
                                         "TLS 1.1 or older." + more, whole=True)
    if not full:
        n = next((i for i, f in enumerate(ctx.findings) if f[1].startswith("Decryption")), None)
        ctx.findings[:] = [(lv, ar, t.replace(more, "") if i != n else t) for i, (lv, ar, t) in enumerate(ctx.findings)]
        return []

    # --- pages (extended report) -------------------------------------------------------------------------
    out = [ctx.h1(TITLE), ctx.p(
        "The SSL proxy decrypts TLS sessions that match a decryption rule, so that App-ID, threat and URL inspection see "
        "the content. It costs CPU for the handshakes, memory per session and a certificate per server name, and the "
        f"{model} can decrypt only a limited number of sessions at the same time. The same proxy also handles TLS that "
        "the firewall terminates itself (GlobalProtect portal and gateway, authentication portal) - "
        + ("this firewall decrypts traffic, so the figures below are mostly decryption."
           if decrypting else "<b>this firewall has no decryption configured</b>, so the figures below are such "
                              "firewall-terminated TLS, not decrypted traffic."))]

    rows = [("Forward proxy (outbound decryption)", "ready" if st.get("forward_ready") == "yes" else "not ready"),
            ("Inbound inspection", "ready" if st.get("inbound_ready") == "yes" else "not ready"),
            ("Decryption rules", f"{rules:,}"),
            ("Certificate revocation check", ", ".join(n for n, k in (("CRL", "verify_crl"), ("OCSP", "verify_ocsp"))
                                                      if st.get(k) == "yes") or "off (no CRL / OCSP)"),
            ("Block sessions with revoked certificates", st.get("block_revoked", "?")),
            ("Certificate cache", "-" if entries is None else f"{entries:,} entries" + (
                f" of {lim_cache:,.0f} ({entries / lim_cache * 100:.0f}%)" if lim_cache else "")),
            ("Decrypted sessions now", f"{val('proxy_sessions_forward'):,.0f}" + (
                f" (limit {lim_sess:,.0f})" if lim_sess else "")),
            ("All SSL proxy sessions now", f"{val('proxy_sessions'):,.0f}")]
    out += [ctx.h2("State"), ctx.table(pd.DataFrame(rows, columns=["", "value"]), [7.0, 7.0])]

    if acc_total:
        fate = pd.Series({lab: acc[k] for k, lab in FATE.items() if acc[k]}).sort_values(ascending=False)
        f, ax = C.fig(C.W, 0.3 * len(fate) + 0.7)
        C.hbar(ax, fate / acc_total * 100, labeler=lambda v: f"{v:.1f}%")
        ax.set_title(f"What happened to the {acc_total:,.0f} TLS sessions the proxy checked since boot")
        out += [ctx.h2("Which TLS sessions are decrypted"), ctx.figure(f, "decrypt_fate",
                "The proxy reads every TLS client hello and then decides by the decryption rules. 'no-decrypt rule' "
                "sessions are checked (certificate, version) but not decrypted.")]

    if not gauge.empty or not prob.empty:
        n = (not gauge.empty) + (not prob.empty)
        f, axes = C.plt.subplots(n, 1, figsize=(C.W, 2.2 * n + 0.4), dpi=150, sharex=True, squeeze=False)
        axes = axes[:, 0]
        i = 0
        if not gauge.empty:
            ax = axes[i]; i += 1
            for col, lab, colr in (("proxy_sessions", "all SSL proxy sessions", C.OTHER),
                                   ("proxy_sessions_forward", "decrypted sessions", C.CAT[0])):
                if col in gauge:
                    ax.plot(gauge.index, gauge[col], color=colr, lw=1.3, label=lab)
            if lim_sess and pd.notna(peak) and peak >= lim_sess * 0.2:
                ax.axhline(lim_sess, color=C.STATUS["critical"], lw=1, ls="--", label=f"limit {lim_sess:,.0f}")
            ax.set_ylim(bottom=0)
            ax.yaxis.set_major_formatter(C.plt.FuncFormatter(lambda v, _p: C.human(v)))
            ax.set_title("Sessions in the SSL proxy at the same time"
                         + (f" (limit of the {model}: {lim_sess:,.0f})" if lim_sess else ""))
            C.legend_below(ax, 3, y=-0.22)
        if not prob.empty:
            ax = axes[i]
            labels = {"proxy_ssl_no_resource": "not decrypted - no resources",
                      "proxy_tls13_downgrade_no_ossl_resource": "TLS 1.3 not proxied - no resources",
                      "proxy_tunnel_taildrop": "packets dropped - proxy queue full",
                      "ssl_tls13_connection_error": "TLS 1.3 connection errors"}
            cols = [k for k in TIME_PROBLEMS if k in prob and prob[k].max() > 0]
            cmap = C.colors_for(cols)
            for k in cols:
                ax.plot(prob.index, prob[k], color=cmap[k], lw=1.2, label=labels[k])
            ax.set_ylim(bottom=0)
            ax.set_ylabel("per second")
            ax.set_title("Proxy problems per second (10-minute intervals)" + ("" if cols else " - none in this window"))
            if cols:
                C.legend_below(ax, 2)
        idx = gauge.index if not gauge.empty else prob.index
        C.time_axis(axes[-1], (idx.max() - idx.min()).total_seconds() / 86400 if len(idx) > 1 else 0)
        out += [ctx.h2("Over time"), ctx.figure(f, "decrypt_time",
                "From the dp-monitor history" + (f" of DP {ds.meta.get('dp')}" if ds.meta.get("dp") else "")
                + ". Resource problems usually show up together with a jump in decrypted sessions.")]

    out += _episodes(ctx, gauge, lim_sess)

    pr = []
    for theme, rx in THEMES:
        for name in [n for n in c.index if re.search(rx, n) and val(n) > 0]:
            pr.append((theme, name, val(name), c.description.get(name, "") if "description" in c else ""))
    pr = pd.DataFrame(pr, columns=["area", "counter", "since boot", "meaning"]).drop_duplicates("counter")
    if not pr.empty:
        out += [ctx.h2("What went wrong"),
                ctx.small("Proxy and TLS counters above zero since the last boot ('show counter global', description "
                          "from PAN-OS)."),
                ctx.table(pr, [3.2, 5.4, 2.0, 6.4], fmt={"since boot": lambda v: f"{v:,.0f}"}, max_rows=40)]

    if not tls.empty and tls["count"].sum():
        vt = tls[tls.kind == "version"].pivot_table(index="name", columns="side", values="count", aggfunc="sum").fillna(0)
        ct = tls[tls.kind == "cipher"].assign(cls=lambda d: d.name.map(_cipher_class))
        ct = ct.pivot_table(index="cls", columns="side", values="count", aggfunc="sum").fillna(0)
        rt = tls[tls.kind == "resume"].pivot_table(index="name", columns="side", values="count", aggfunc="sum").fillna(0)

        def shares(t):
            t = t.loc[t.sum(axis=1) > 0]
            for s in ("client", "server"):
                if s not in t:
                    t[s] = 0
            tot = t[["client", "server"]].sum()
            pct = lambda col, total: col / total * 100 if total else np.nan
            return pd.DataFrame({"": t.index, "client side": t.client, "share": pct(t.client, tot.client),
                                 "server side": t.server, "share ": pct(t.server, tot.server)}
                                ).sort_values("client side", ascending=False)
        num, share = lambda v: f"{v:,.0f}", lambda v: "-" if pd.isna(v) else f"{v:.1f}%"
        fmt = {"client side": num, "server side": num, "share": share, "share ": share}
        w = [6.0, 2.4, 1.6, 2.4, 1.6]
        out += [ctx.h2("TLS versions and ciphers"),
                ctx.small("Handshakes since boot. <b>client side</b>: between the client and the firewall, <b>server "
                          "side</b>: between the firewall and the server. TLS 1.0/1.1, CBC suites and RSA key exchange "
                          "(no forward secrecy) are outdated; TLS 1.3 and ECDHE with GCM/ChaCha20 are current."),
                ctx.table(shares(vt), w, fmt=fmt), ctx.table(shares(ct), w, fmt=fmt)]
        if not rt.empty:
            out += [ctx.small("<b>Session resumption</b> reuses an earlier handshake and saves its CPU work; many "
                              "failed resumptions mean full handshakes."), ctx.table(shares(rt), w, fmt=fmt)]

    out += _from_logs(ctx)

    if ds.has("decrypt_exclude"):
        ex = ds["decrypt_exclude"].groupby("reason", as_index=False)["count"].sum()
        ex = ex.sort_values("count", ascending=False)
        ex["meaning"] = ex.reason.map(EXCLUDE_REASON).fillna("")
        out += [ctx.h2("Excluded from decryption (cache)"),
                ctx.small("Servers the proxy currently skips and why (server names left out)."),
                ctx.table(ex[["reason", "count", "meaning"]], [5.0, 2.0, 9.0], fmt={"count": lambda v: f"{v:,.0f}"})]

    if ds.has("dp_pow_interval"):
        p = ds["dp_pow_interval"]
        cr = p[(p.kind == "func") & (p.feature == "Decryption & crypto")].groupby("ts").pct.sum()
        if len(cr):
            out.append(ctx.p(f"<b>CPU:</b> decryption and crypto functions used {cr.median():.2f}% of the DP "
                             f"capacity in a typical 10-minute interval and at most {cr.max():.2f}% (see 'What "
                             "consumes dataplane CPU')."))
    out += _conclusion(ctx, dict(decrypting=decrypting, val=val, acc=acc, acc_total=acc_total, rules=rules,
                                 peak=peak, peak_ts=peak_ts, lim_sess=lim_sess, lim_cache=lim_cache,
                                 entries=entries, prob=prob, tls=tls, model=model))
    return out


# decryption log reasons -> what they usually mean (for the conclusion)
LOG_HINTS = [
    (r"version mismatch|unsupported (ssl )?(protocol|version)",
     "clients use TLS versions the decryption profile does not allow - check its minimum and maximum version"),
    (r"cipher", "clients offer only ciphers the decryption profile does not allow"),
    (r"CertificateUnknown|BadCertificate|UnknownCA|unknown ca",
     "clients reject the firewall's certificate - the forward-trust CA is missing on those clients, or the app pins "
     "its certificate (put such servers on the decryption exclusion list)"),
    (r"close notify|protocol error|reset",
     "clients or apps abort the handshake - typical for certificate pinning or Encrypted Client Hello"),
]


def _window(ds) -> str:
    """Where the time series come from: 'dp-monitor window' (TSF) or 'collected samples' (live)."""
    return "collected samples" if ds.source == "live" else "dp-monitor window"


def _short_error(e: str) -> str:
    """'Unsupported cipher. Supported client cipher bitmask: 0x9c..' -> 'Unsupported cipher' (details vary per session)."""
    e = str(e).strip()
    return re.split(r"\.\s|\. *$|: 0x", e)[0].strip() or e


def _log_failures(ds) -> pd.DataFrame:
    """Decryption log entries with an error (live collection only - a TSF holds no logs)."""
    if not ds.has("logs_decryption"):
        return pd.DataFrame()
    lg = ds["logs_decryption"]
    if "error" not in lg.columns:
        return pd.DataFrame()
    f = lg[lg.error.fillna("").str.strip() != ""].copy()
    f["reason"] = f.error.map(_short_error)
    return f


def _from_logs(ctx) -> list:
    ds = ctx.ds
    if not ds.has("logs_decryption"):
        return []
    lg, f = ds["logs_decryption"], _log_failures(ds)
    span = f"{lg.receive_time.min():%d.%m.%Y} - {lg.receive_time.max():%d.%m.%Y}"
    out = [ctx.h2("From the decryption log"),
           ctx.small(f"{len(lg):,} decryption log entries ({span}), {len(f):,} of them with an error. The firewall "
                     "logs only what the decryption rules' log settings ask for (usually the failures).")]
    if f.empty:
        return out
    r = f.groupby("reason").agg(count=("reason", "size"), servers=("sni", "nunique")).sort_values("count", ascending=False)
    r["share"] = r["count"] / len(f) * 100
    tab = r.reset_index()[["reason", "count", "share", "servers"]].rename(columns={"servers": "servers (SNI)"})
    out.append(ctx.table(tab,
                         [9.4, 2.2, 1.8, 2.4], fmt={"count": lambda v: f"{v:,.0f}", "share": lambda v: f"{v:.0f}%",
                                                   "servers (SNI)": lambda v: f"{v:,.0f}"}, max_rows=12))
    if "sni" in f.columns and f.sni.notna().any():
        top = f.dropna(subset=["sni"]).groupby("sni").agg(
            count=("sni", "size"), reason=("reason", lambda x: x.value_counts().index[0])).sort_values(
            "count", ascending=False).head(10).reset_index()
        out += [ctx.small("Servers with the most failures (server name from the client hello) and their most common "
                          "error - often apps with certificate pinning or clients that reject the firewall's "
                          "certificate; such servers belong on the decryption exclusion list."),
                ctx.table(top.rename(columns={"sni": "server"}), [6.4, 2.0, 7.4],
                          fmt={"count": lambda v: f"{v:,.0f}"})]
    if "tls_version" in f.columns and f.tls_version.notna().any():
        v = f.tls_version.fillna("unknown").replace("", "unknown").value_counts()
        out.append(ctx.small("TLS versions of the failed sessions: " + ", ".join(
            f"{k} {n / len(f) * 100:.0f}%" for k, n in v.head(5).items()) + "."))
    top_r = r.index[0]
    ctx.find("info", "Decryption", f"Decryption log: {len(f):,} failed sessions ({span}); most common: "
                                   f"{top_r} ({r['share'].iloc[0]:.0f}%).", whole=True)
    return out


def _episodes(ctx, gauge: pd.DataFrame, lim_sess) -> list:
    """Periods with TLS/SSL failures from the 10-minute counter history, with a rule-based possible cause."""
    ds = ctx.ds
    if not ds.has("dp_counter_rates"):
        return []
    r = ds["dp_counter_rates"]
    rates = r[r.name.isin(list(FAIL) + ["pkt_recv", "proxy_acc_convert_to_forward_proxy"])].pivot_table(
        index="ts", columns="name", values="rate").sort_index().fillna(0)
    fail = [k for k in FAIL if k in rates]
    if not fail or len(rates) < 3:
        return []
    dt = rates.index.to_series().diff().dt.total_seconds().fillna(600)
    cnt = rates[fail].mul(dt, axis=0)  # events per interval
    # usual level = median over all intervals: rare failures count from EPISODE_MIN events, steady ones from a spike
    hot = pd.DataFrame({k: (cnt[k] >= EPISODE_MIN.get(k, EPISODE_MIN_SESSIONS))
                        & (cnt[k] >= EPISODE_FACTOR * cnt[k].median()) for k in fail})
    act = hot.any(axis=1)
    if not act.any():
        return [ctx.h2("Episodes"), ctx.small("No period with clearly more TLS/SSL failures than usual in the "
                                              f"{_window(ds)}.")]
    step = pd.Timedelta(seconds=float(dt.median()))
    idx = list(act[act].index)
    groups, cur = [], [idx[0]]
    for t in idx[1:]:  # merge intervals at most one interval apart
        if t - cur[-1] <= 2 * step:
            cur.append(t)
        else:
            groups.append(cur)
            cur = [t]
    groups.append(cur)

    fwd = gauge["proxy_sessions_forward"] if "proxy_sessions_forward" in gauge else pd.Series(dtype=float)
    usual_fwd = fwd.median() if len(fwd) else np.nan
    pps = rates["pkt_recv"] if "pkt_recv" in rates else pd.Series(dtype=float)
    load = pd.Series(dtype=float)
    if ds.has("dpm_minute"):
        m = ds["dpm_minute"]
        load = m[m.core.isin(ds.meta.get("dp_cores") or [])].groupby("ts")["avg"].mean()
    com = ds["commits"] if ds.has("commits") else pd.DataFrame(columns=["ts", "job", "kind"])
    com = com[com.kind == "configuration"]
    logf = _log_failures(ds)

    rows = []
    for g in groups:
        start, end = g[0] - step, g[-1]
        span = (cnt.index > start) & (cnt.index <= end)
        # only the counters that made this an episode count - single events of others are noise
        sig = [k for k in fail if hot.loc[hot.index.isin(g), k].any()]
        tot = cnt[span][sig].sum().sort_values(ascending=False)
        what = "; ".join(f"{FAIL[k]}: {v:,.0f}" for k, v in tot.head(4).items()) + ("; ..." if len(tot) > 4 else "")
        f_in = fwd[(fwd.index > start) & (fwd.index <= end)]
        f_peak = f_in.max() if len(f_in) else np.nan
        ld = load[(load.index > start) & (load.index <= end)].max() if len(load) else np.nan
        p_in = pps[span].max() if len(pps) else np.nan
        causes = []
        cm = com[(com.ts >= start - COMMIT_BEFORE) & (com.ts <= end)]
        jump = pd.notna(f_peak) and pd.notna(usual_fwd) and f_peak >= max(0.05 * lim_sess if lim_sess else 100,
                                                                          3 * usual_fwd)
        if len(cm):
            causes.append("configuration commit at " + ", ".join(f"{t:%H:%M}" for t in cm.ts)
                          + (" (e.g. a new or changed decryption rule)" if jump else ""))
        if jump:
            causes.append(f"jump in decrypted sessions to {f_peak:,.0f} (usually {usual_fwd:,.0f})")
        res = {"proxy_ssl_no_resource", "proxy_tls13_downgrade_no_ossl_resource"} & set(tot.index)
        if res:
            if lim_sess and pd.notna(f_peak) and f_peak >= 0.8 * lim_sess:
                causes.append("decryption session limit nearly reached")
            else:
                causes.append("proxy resources exhausted (memory, TLS 1.3 contexts) - not the session limit"
                              + (" or the CPU" if pd.notna(ld) and ld < 50 else ""))
        if pd.notna(ld) and ld >= 80:
            causes.append(f"dataplane overloaded ({ld:.0f}% load)")
        if "proxy_tunnel_taildrop" in tot.index and not res:
            causes.append("burst of traffic through the SSL proxy filled its send queue"
                          + (f" (busy time, {p_in:,.0f} packets/s)" if len(pps) and pd.notna(p_in)
                             and p_in >= 1.5 * pps.median() else ""))
        if "ssl_tls13_connection_error" in tot.index and res:
            causes.append("TLS 1.3 errors follow the resource shortage")
        if {"proxy_ssl_untrusted_cert", "proxy_ssl_expired_cert", "proxy_ssl_invalid_cert"} & set(tot.index):
            causes.append("servers with untrusted, expired or invalid certificates were contacted")
        if {"proxy_ssl_unsupported", "proxy_ssl_unsupported_cipher", "proxy_client_hello_failed"} & set(tot.index):
            causes.append("clients or servers with outdated or non-standard TLS")
        if {"proxy_url_request_pkt_drop", "proxy_url_request_timeout"} & set(tot.index):
            causes.append("slow URL category lookups (cloud connection)")
        lf = logf[(logf.receive_time > start) & (logf.receive_time <= end)] if len(logf) else logf
        if len(lf):
            causes.append(f"decryption log: {lf.reason.value_counts().index[0]} "
                          f"({lf.reason.value_counts().iloc[0]:,} of {len(lf):,} logged failures)")
        rows.append((start, end, end - start, what, f_peak, "; ".join(causes) or "-",
                     # for the conclusion: which kinds of failure, how many, commit before / jump in sessions
                     sorted(sig), float(tot.sum()), bool(len(cm)), bool(jump), p_in, ld, tot.to_dict()))

    tab = pd.DataFrame(rows, columns=["from", "to", "duration", "what failed", "decrypted sessions", "possible cause",
                                      "_kinds", "_failures", "_commit", "_jump", "_pps", "_load", "_counts"])
    # how many periods would have a commit in [start - COMMIT_BEFORE, end] by chance: for each period, the share of
    # start times in the window for which a period of that length would contain a commit
    t0, t1 = cnt.index.min(), cnt.index.max()
    grid = pd.date_range(t0, t1, freq="1min") if t1 > t0 else pd.DatetimeIndex([])
    work = all(WORK_HOURS[0] <= t.hour < WORK_HOURS[1] for t in tab["from"])
    if work:  # commits and periods both happen in working hours - compare like with like
        grid = grid[(grid.hour >= WORK_HOURS[0]) & (grid.hour < WORK_HOURS[1])]
    ds.meta["tls_commit_work_hours"] = work
    cts = com.ts[(com.ts >= t0 - COMMIT_BEFORE) & (com.ts <= t1 + pd.Timedelta(days=1))].sort_values().values
    exp = 0.0
    for dur in tab.duration:
        if len(grid) and len(cts):
            lo = np.searchsorted(cts, (grid - COMMIT_BEFORE).values, side="left")
            hi = np.searchsorted(cts, (grid + dur).values, side="right")
            exp += float((hi > lo).mean())
    ds.meta["tls_commit_expected"] = exp
    ds.meta["tls_commits_in_window"] = int(((com.ts >= t0) & (com.ts <= t1)).sum())
    ds.meta["tls_window"] = (t0, t1)
    dur = lambda d: (f"{d.total_seconds() / 3600:.1f} h" if d >= pd.Timedelta(hours=2)
                     else f"{d.total_seconds() / 60:.0f} min")
    out = [ctx.h2("Episodes"),
           ctx.small("Periods with clearly more TLS/SSL failures than usual (a 10-minute interval counts when a failure "
                     f"counter has at least {EPISODE_MIN_SESSIONS} failed sessions - "
                     f"{EPISODE_MIN['proxy_tunnel_taildrop']:,} dropped packets for the proxy queue - and "
                     f"{EPISODE_FACTOR}x its usual level; intervals at most one apart are merged). 'decrypted "
                     "sessions' is the peak in the episode"
                     + (f" - usually {usual_fwd:,.0f}" if pd.notna(usual_fwd) else "") + ". The possible cause is "
                     "derived from what changed at the same time - a hint, not a proof."),
           ctx.table(tab[tab.columns[:6]], [1.9, 1.3, 1.4, 5.0, 1.8, 5.6],
                     fmt={"from": lambda t: f"{t:%d.%m. %H:%M}", "to": lambda t: f"{t:%H:%M}", "duration": dur,
                          "decrypted sessions": lambda v: "-" if pd.isna(v) else f"{v:,.0f}"}, max_rows=30)]
    if len(tab) > 30:
        out.append(ctx.small(f"{len(tab) - 30} more episodes in the CSV file (tls_episodes.csv)."))
    ds.t["tls_episodes"] = tab
    try:  # the data files are written before the sections run - add this one
        (ctx.outdir / "data").mkdir(parents=True, exist_ok=True)
        tab[tab.columns[:6]].to_csv(ctx.outdir / "data" / "tls_episodes.csv", index=False)
    except OSError:
        pass
    return out


# kinds of problem periods: counters, heading, what to do (tls13: only when not part of a resource shortage)
PERIOD_KINDS = [
    ("resources", {"proxy_ssl_no_resource", "proxy_tls13_downgrade_no_ossl_resource"}, "Proxy out of resources",
     "find out what changed before these periods (decryption rules, amount of decrypted traffic) and check the proxy "
     "memory ('show system setting ssl-decrypt memory') at such a time; if it repeats, open a case with Palo Alto "
     "Networks support"),
    ("queue", {"proxy_tunnel_taildrop"}, "Proxy send queue full",
     "the queue also carries sessions the proxy only checks (no-decrypt rules, client hello inspection), so it can "
     "overflow without much decryption; retransmissions cover the drops at the cost of latency - if they grow or "
     "users notice delays, open a case with Palo Alto Networks support"),
    ("tls13", {"ssl_tls13_connection_error", "proxy_tls13_server_timedout"}, "TLS 1.3 errors",
     "check which servers fail in the decryption log; servers that break TLS 1.3 proxying belong on the exclusion "
     "list"),
    ("certs", {"proxy_ssl_untrusted_cert", "proxy_ssl_expired_cert", "proxy_ssl_invalid_cert"}, "Server certificates",
     "decide in the decryption profile whether sessions with such certificates are blocked"),
    ("unsupported", {"proxy_ssl_unsupported", "proxy_ssl_unsupported_cipher", "proxy_client_hello_failed",
                     "ssl_ossl_cipher_set_fail"}, "Unsupported or unreadable TLS",
     "old or non-standard clients and servers - allow their versions and ciphers in the decryption profile or exclude "
     "them"),
    ("url", {"proxy_url_request_pkt_drop", "proxy_url_request_timeout"}, "URL category lookups",
     "the proxy waited for URL categories from the cloud - check the firewall's connection to the URL filtering "
     "cloud"),
]
WORK_HOURS = (6, 19)  # episodes starting in [06:00, 19:00) count as working hours


def _periods(ctx, lim_sess) -> tuple[list, list]:
    """Conclusion sub-section 'Problem periods': the episodes as a whole - per kind of problem when, how often, how
    long, the worst one, what they have in common; whether commits explain them more often than chance would."""
    ds = ctx.ds
    if "tls_episodes" not in ds.t:
        return [], []
    ep = ds.t["tls_episodes"]
    out = [ctx.h3("Problem periods")]
    win = _window(ds)
    if ep.empty:
        out.append(ctx.p(f"No period in the {win} with clearly more TLS/SSL failures than usual."))
        return out, []
    days = sorted({t.date() for t in ep["from"]})
    total = sum((d for d in ep.duration), pd.Timedelta(0))
    fmt_d = lambda x: (f"{x.total_seconds() / 3600:.1f} h" if x >= pd.Timedelta(hours=2)
                       else f"{x.total_seconds() / 60:.0f} min")
    t0, t1 = ds.meta.get("tls_window", (None, None))
    span = f" in {(t1 - t0).total_seconds() / 86400:.1f} days" if t0 is not None else ""
    out.append(ctx.p(f"The {win} holds <b>{len(ep)} problem period{'s' if len(ep) != 1 else ''}</b>{span}, "
                     f"{fmt_d(total)} in total, on {len(days)} day{'s' if len(days) != 1 else ''}."))
    r = ds["dp_counter_rates"] if ds.has("dp_counter_rates") else pd.DataFrame(columns=["name", "rate"])
    pps_usual = r[r.name == "pkt_recv"].rate.median() if len(r) else np.nan
    todo = []
    res_eps = {i for i, k in enumerate(ep._kinds) if set(k) & PERIOD_KINDS[0][1]}
    for key, names, title, advice in PERIOD_KINDS:
        idx = [i for i, k in enumerate(ep._kinds) if set(k) & names and not (key == "tls13" and i in res_eps)]
        if not idx:
            continue
        e = ep.iloc[idx]
        hours = [t.hour for t in e["from"]]
        when = ("all during working hours" if all(WORK_HOURS[0] <= h < WORK_HOURS[1] for h in hours) else
                "all outside working hours" if not any(WORK_HOURS[0] <= h < WORK_HOURS[1] for h in hours) else
                "during the day and at night")
        edays = sorted({t.date() for t in e["from"]})
        own = e._counts.map(lambda c: sum(v for k, v in c.items() if k in names))
        worst = e.loc[own.idxmax()]
        detail = "; ".join(f"{FAIL[k]}: {v:,.0f}" for k, v in worst._counts.items() if k in names)
        if len(e) == 1:
            when = when.replace("all ", "")
        txt = (f"<b>{title}:</b> {len(e)} period{'s' if len(e) != 1 else ''}"
               + (f" on {len(edays)} days" if len(edays) > 1 else f" on {edays[0]:%d.%m.}") + f", {when}, "
               + (f"{fmt_d(min(e.duration))} to {fmt_d(max(e.duration))} each, {own.sum():,.0f} in total"
                  if len(e) > 1 else fmt_d(worst.duration))
               + f"; the largest {worst['from']:%d.%m. %H:%M}-{worst.to:%H:%M} ({detail}).")
        dec = e["decrypted sessions"]
        if dec.notna().any():
            low_lim = 0.05 * lim_sess if lim_sess else 100
            n_low = int((dec < low_lim).sum())
            if len(e) > 1 and n_low:
                txt += (f" In {'all of them' if n_low == len(e) else f'{n_low} of the {len(e)}'} decryption itself was "
                        f"low (under {low_lim:,.0f} decrypted sessions)"
                        + (f"; the others reached up to {dec.max():,.0f}." if n_low < len(e) else "."))
            else:
                txt += f" Up to {dec.max():,.0f} decrypted sessions at the same time" + (
                    f" ({dec.max() / lim_sess * 100:.0f}% of the limit)." if lim_sess else ".")
        busy = (e._pps >= 1.5 * pps_usual).sum() if pd.notna(pps_usual) else 0
        if busy and busy >= len(e) / 2:
            txt += (f" {'All' if busy == len(e) else f'{busy} of {len(e)}'} fall into busy times (up to "
                    f"{e._pps.max():,.0f} packets/s, usually {pps_usual:,.0f}).")
        if e._load.max() >= 80:
            txt += f" The dataplane was at up to {e._load.max():.0f}% load."
        if len(edays) > 1 and len(e) >= 3:
            txt += " It recurs - a pattern, not a one-off."
        out.append(ctx.p("- " + txt))
        todo.append((key, f"{title}: {advice}"))

    worst = ep.loc[ep._failures.idxmax()]
    out.append(ctx.p(f"<b>The heaviest period</b> was {worst['from']:%d.%m. %H:%M}-{worst.to:%H:%M} "
                     f"({fmt_d(worst.duration)}): {worst['what failed']}. Possible cause: {worst['possible cause']}."))

    com = ds["commits"] if ds.has("commits") else pd.DataFrame(columns=["ts", "kind"])
    com = com[com.kind == "configuration"]
    if len(com):
        after = [bool(((com.ts >= a - COMMIT_BEFORE) & (com.ts <= b)).any()) for a, b in zip(ep["from"], ep.to)]
        n_after, exp = sum(after), ds.meta.get("tls_commit_expected", 0.0)
        txt = (f"<b>Configuration commits:</b> {n_after} of {len(ep)} periods had a configuration commit up to "
               f"{COMMIT_BEFORE.total_seconds() / 60:.0f} minutes before or during them. With "
               f"{ds.meta.get('tls_commits_in_window', len(com))} commits in the {win}, about {exp:.1f} would by "
               "chance" + (" (counted for working hours only, since all periods fall into them)"
                           if ds.meta.get("tls_commit_work_hours") else "") + ". ")
        jump_after = [i for i, a in enumerate(after) if a and ep._jump.iloc[i]]
        if n_after >= 2 and n_after >= 2 * max(exp, 0.5):
            txt += "That is clearly more than chance - look at what those commits changed."
            todo.append(("commits", "Configuration commits: compare what the commits right before the problem "
                                    "periods changed - they line up more often than chance"))
        elif jump_after:
            txt += ("Overall that is not more than chance, but where the decrypted sessions jumped right after a "
                    "commit (" + ", ".join(f"{ep['from'].iloc[i]:%d.%m. %H:%M}" for i in jump_after)
                    + "), that commit is the likely trigger.")
        else:
            txt += "So commits don't explain these periods."
        out.append(ctx.p(txt))
    return out, todo


def _conclusion(ctx, d: dict) -> list:
    """Summary of the section in a few sentences: verdict first, then what the figures mean and what to check.
    Measured facts are stated as such; interpretations are marked ('points to', 'likely')."""
    ds, val, model = ctx.ds, d["val"], d["model"]
    pts, todo = [], []
    if not d["decrypting"]:
        txt = (f"The {model} does not decrypt traffic. Its SSL proxy only handles TLS the firewall terminates itself "
               f"({val('proxy_process'):,.0f} sessions since boot, e.g. GlobalProtect), so App-ID, threat and URL "
               "inspection see TLS traffic only up to the handshake (server name, certificate).")
        return [ctx.h2("Conclusion"), ctx.p(txt)]

    # coverage
    acc, tot = d["acc"], d["acc_total"]
    if tot:
        dec = (acc["forward_proxy"] + acc["inbound_proxy"]) / tot * 100
        nod, none = acc["nodecrypt_proxy"] / tot * 100, acc["no_proxy"] / tot * 100
        pts.append(f"<b>Coverage:</b> {dec:.1f}% of the TLS sessions are decrypted; {nod:.0f}% are deliberately "
                   f"not decrypted (no-decrypt rule) and {none:.0f}% match no decryption rule. For "
                   f"{100 - dec:.0f}% of the TLS traffic, threat and URL inspection see only the handshake."
                   + (" That is a narrow scope - usually a choice in the decryption rules, worth confirming."
                      if dec < 20 else ""))

    # headroom and the resource problems
    peak, lim = d["peak"], d["lim_sess"]
    load = np.nan
    if d["peak_ts"] is not None and ds.has("dpm_minute"):
        m = ds["dpm_minute"]
        m = m[m.core.isin(ds.meta.get("dp_cores") or [])].groupby("ts")["avg"].mean()
        near = m[(m.index > d["peak_ts"] - pd.Timedelta(minutes=10)) & (m.index <= d["peak_ts"])]
        load = near.mean() if len(near) else np.nan
    if pd.notna(peak) and lim:
        pct = peak / lim * 100
        pts.append(f"<b>Headroom:</b> at most {peak:,.0f} decrypted sessions at the same time - {pct:.0f}% of the "
                   f"{model}'s {lim:,.0f}, " + ("far from the limit." if pct < 50 else "getting close to the limit."
                                                if pct < 80 else "close to the limit."))
    no_res, t13 = val("proxy_ssl_no_resource"), val("proxy_tls13_downgrade_no_ossl_resource")
    prob = d["prob"]
    if no_res or t13:
        res = prob[[k for k in RESOURCE if k in prob]].sum(axis=1) if len(prob) else pd.Series(dtype=float)
        when = _span(res)
        txt = (f"<b>Proxy resources:</b> {no_res:,.0f} sessions were not decrypted and {t13:,.0f} TLS 1.3 "
               "handshakes not proxied as TLS 1.3 because the proxy ran out of resources")
        if when:
            txt += f" - in the {_window(ds)} all of it on {when}"
            pos = res[res > 0]
            if d["peak_ts"] is not None and len(pos) and pos.index.min() <= d["peak_ts"] <= pos.index.max():
                txt += f", together with the peak of {peak:,.0f} decrypted sessions"
        txt += "."
        low = pd.notna(peak) and lim and peak / lim < 0.5
        if low:
            txt += (f" Sessions were at {peak / lim * 100:.0f}% of the limit" + (f" and the dataplane at {load:.0f}% "
                    "load" if pd.notna(load) else "") + " at that time, so neither the session limit nor the CPU "
                    "was the bottleneck - it points to another proxy resource (proxy memory, TLS 1.3 contexts).")
            todo.append(("resources", "find out what changed shortly before the resource errors (e.g. a new or wider "
                                      "decryption rule) and check the proxy memory ('show system setting ssl-decrypt "
                                      "memory') at a busy time; if it repeats, open a case with Palo Alto Networks "
                                      "support"))
        else:
            todo.append(("resources", "reduce the decrypted traffic or plan a larger model - the proxy runs out of "
                                      "resources"))
        pts.append(txt)
    td = val("proxy_tunnel_taildrop")
    if td >= TAILDROP_NOTICE:
        n = int((prob.get("proxy_tunnel_taildrop", pd.Series(dtype=float)) > 0).sum()) if len(prob) else 0
        pts.append(f"<b>Proxy queue:</b> {td:,.0f} packets were dropped because the proxy's send queue was full"
                   + (f" - in {n} of {len(prob)} 10-minute intervals, so it recurs, also outside the resource "
                      "problem above." if n > 2 else ".")
                   + " Retransmissions usually cover such drops, at the cost of latency for the decrypted sessions.")
    if d["entries"] and d["lim_cache"] and d["entries"] >= d["lim_cache"] * 0.95:
        pts.append(f"<b>Certificate cache:</b> full ({d['entries']:,.0f} of {d['lim_cache']:,.0f}, a fixed size per "
                   "model). Certificates for servers that dropped out of the cache are generated again - extra "
                   f"handshake work ({val('ssl_cert_cache_miss'):,.0f} misses since boot), but not a fault.")

    # TLS quality
    tls = d["tls"]
    ver = tls[(tls.kind == "version") & (tls.side == "client")].set_index("name")["count"]
    if ver.sum():
        t13s = ver[ver.index.str.startswith("TLS1.3")].sum() / ver.sum() * 100
        legacy = ver[ver.index.str.match(r"^(SSL|TLS1\.[01])")].sum() / ver.sum() * 100
        cip = tls[(tls.kind == "cipher") & (tls.side == "client")]
        old = cip[cip.name.map(_cipher_class).str.startswith(("RSA key", "weak"))]["count"].sum()
        nopfs = old / max(cip["count"].sum(), 1) * 100
        res = tls[(tls.kind == "resume") & (tls.side == "client")].set_index("name")["count"]
        ok, failed = res.get("Resumed Locally", 0), res.get("Resumed Failed", 0)
        txt = (f"<b>TLS quality:</b> {t13s:.0f}% of the client connections through the proxy use TLS 1.3, "
               + (f"{legacy:.1f}% TLS 1.1 or older" if legacy >= 0.1 else "none use TLS 1.1 or older") + ", "
               + (f"{nopfs:.1f}% ciphers without forward secrecy" if nopfs >= 0.1 else
                  "no ciphers without forward secrecy") + " - "
               + ("a current mix." if legacy < 1 and nopfs < 5 else "outdated clients or servers are left."))
        if failed > ok and failed:
            txt += (f" Session resumption fails more often than it works ({failed:,.0f} failed, {ok:,.0f} resumed), "
                    "so most handshakes are full ones.")
        pts.append(txt)
    bad = {k: val(k) for k in ("proxy_ssl_untrusted_cert", "proxy_ssl_expired_cert", "proxy_ssl_invalid_cert") if val(k)}
    if bad:
        pts.append("<b>Certificates:</b> " + ", ".join(f"{v:,.0f} {k.split('_')[2]}" for k, v in bad.items())
                   + " server certificates since boot. Whether such sessions are blocked depends on the decryption "
                     "profile - worth checking against your policy.")
        todo.append(("certs", "check the decryption profile: block sessions with untrusted, expired or invalid server "
                              "certificates"))
    lf = _log_failures(ds)
    if len(lf):
        r = lf.reason.value_counts()
        hints = []
        for rx, hint in LOG_HINTS:
            n = int(r[r.index.str.contains(rx, case=False, regex=True)].sum())
            if n and n / len(lf) >= 0.1 and hint not in [h for h, _ in hints]:
                hints.append((hint, n / len(lf) * 100))
        pts.append(f"<b>Decryption log:</b> {len(lf):,} failed sessions, most often '{r.index[0]}' "
                   f"({r.iloc[0] / len(lf) * 100:.0f}%)."
                   + "".join(f" {h[0].upper() + h[1:]} ({p:.0f}%)." for h, p in hints))
        if hints:
            todo.append(("log", "go through the failures in 'From the decryption log': fix the decryption profile where "
                                "versions or ciphers don't match, and exclude servers that reject the firewall's "
                                "certificate"))
    if ds.has("dp_pow_interval"):
        p = ds["dp_pow_interval"]
        cr = p[(p.kind == "func") & (p.feature == "Decryption & crypto")].groupby("ts").pct.sum()
        if len(cr):
            pts.append(f"<b>CPU cost:</b> at most {cr.max():.1f}% of the DP capacity went into decryption - "
                       + ("small." if cr.max() < 10 else "a noticeable part of the load."))

    n_dec = acc["forward_proxy"] + acc["inbound_proxy"]
    if tot and not n_dec:
        share_txt = (f" Nothing has been decrypted since boot, although {d['rules']} decryption "
                     f"rule{'s' if d['rules'] != 1 else ''} exist{'s' if d['rules'] == 1 else ''}.")
    elif tot and n_dec / tot < 0.2:
        share_txt = f" It decrypts only a small share of the TLS traffic ({n_dec / tot * 100:.0f}%)."
    else:
        share_txt = ""
    serious = (no_res or t13) or (pd.notna(peak) and lim and peak / lim >= PEAK_NOTICE / 100)
    verdict = (f"Decryption on this {model} " + ("has a capacity problem: " if serious else "runs without capacity "
               "problems") + ("the SSL proxy ran out of resources although sessions and CPU were well below their "
                              "limits." if serious and pd.notna(peak) and lim and peak / lim < 0.5 else
                              "it is close to its limits." if serious else ".")
               + share_txt)
    out = [ctx.h2("Conclusion"), ctx.p(f"<b>{verdict}</b>")] + [ctx.p("- " + t) for t in pts]
    per, per_todo = _periods(ctx, d["lim_sess"])
    out += per
    items = dict(todo)
    items.update(per_todo)  # the period view replaces the general advice of the same kind
    if items:
        out.append(ctx.p("<b>To check:</b>"))
        out += [ctx.p(f"- {t[0].upper() + t[1:]}.") for t in items.values()]
    return out
