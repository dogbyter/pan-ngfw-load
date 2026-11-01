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
        parts = ([f"{no_res:,.0f} sessions not decrypted"] if no_res else []) + \
                ([f"{tls13_res:,.0f} TLS 1.3 handshakes not proxied as TLS 1.3"] if tls13_res else [])
        ctx.find("warning" if no_res + tls13_res >= RES_WARN else "notice", "Decryption",
                 "Out of proxy resources since boot: " + " and ".join(parts)
                 + (f" (in the dp-monitor window: {when})" if when else "") + "." + more, whole=not when)
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
    return out
