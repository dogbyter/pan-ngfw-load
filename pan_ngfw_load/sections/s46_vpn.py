"""Extended: IPsec VPN overview - tunnels and their state, encryption, traffic per tunnel interface since boot,
ESP rates over time and the share of dataplane CPU spent on IPsec."""

import pandas as pd

from .. import charts as C
from .. import knowledge as K

TITLE = "IPsec VPN"


def _alg_note(alg: str) -> str:
    a = alg.upper()
    if "/G" in a or "GCM" in a:
        return "AES-GCM (encryption + integrity in one pass)"
    if "/A" in a:
        return "AES-CBC + separate hash"
    if "3DES" in a or "/D" in a:
        return "3DES (outdated, slow)"
    return ""


def build(ctx):
    ds = ctx.ds
    tun = ds["vpn_tunnels"] if ds.has("vpn_tunnels") else pd.DataFrame()
    ifc = ds["if_counters"] if ds.has("if_counters") else pd.DataFrame(columns=["interface"])
    tif = ifc[ifc.interface.str.match(r"^tunnel\.\d+$")] if not ifc.empty else ifc
    if tun.empty and (tif.empty or (tif.rx_bytes.sum() + tif.tx_bytes.sum()) == 0):
        return []
    out = [ctx.h1(TITLE), ctx.p(
        "IPsec costs the dataplane more per packet than plain forwarding: every packet is encrypted or decrypted "
        "and authenticated. All packets of one tunnel arrive with the same outer addresses, so the ports deliver "
        "them to the same core - a single busy tunnel can load one core more than the others (see the core-spike "
        "section). This section lists the tunnels, how they are encrypted and how much traffic they carry.")]

    # --- tunnels ------------------------------------------------------------------------
    if not tun.empty:
        t = tun.copy()
        if ds.has("vpn_sa"):
            t = t.merge(ds["vpn_sa"], on="tunnel_id", how="left")
        else:
            t["algorithm"] = ""
        t["base"] = t.name.str.split(":").str[0]
        g = t.groupby("base").agg(proxy_ids=("tunnel_id", "size"), up=("state", lambda s: (s == "active").sum()),
                                  algorithm=("algorithm", lambda s: ", ".join(sorted(set(x for x in s if isinstance(x, str) and x)))))
        g = g.reset_index().rename(columns={"base": "tunnel"})
        g["state"] = g.up.astype(str) + " of " + g.proxy_ids.astype(str) + " up"
        g["encryption"] = g.algorithm.map(lambda a: _alg_note(a.split(",")[0]) if a else "")
        out.append(ctx.h2("Tunnels"))
        out.append(ctx.small("One row per IPsec tunnel; tunnels with proxy IDs have one SA pair per proxy ID "
                             "('show vpn flow', 'show vpn ipsec-sa')."))
        out.append(ctx.table(g[["tunnel", "state", "algorithm", "encryption"]], [5.0, 2.4, 5.0, 4.6]))
        down = t[t.state != "active"]
        ctx.find("notice" if len(down) else "info", "VPN",
                 f"{len(g)} IPsec tunnel{'s' if len(g) > 1 else ''} with {len(t)} SA pair{'s' if len(t) > 1 else ''}"
                 + (f"; {len(down)} not up ({', '.join(down.name.head(5))})." if len(down) else ", all up."))
        if g.encryption.str.startswith("AES-CBC").any() and not g.encryption.str.startswith("AES-GCM").all():
            out.append(ctx.p(
                "<b>Encryption:</b> AES-GCM encrypts and authenticates in one pass and is the cheapest option for the "
                "dataplane. AES-CBC needs a separate hash (SHA) pass over every packet. Where both ends support it, "
                "offering AES-GCM first in the IPsec crypto profile lowers the CPU cost of busy tunnels."))

    # --- traffic per tunnel interface --------------------------------------------------
    if not tif.empty and (tif.rx_bytes.sum() + tif.tx_bytes.sum()) > 0:
        x = tif.copy()
        x["total"] = x.rx_bytes + x.tx_bytes
        x = x[x.total > 0].sort_values("total", ascending=False)
        x["share"] = x.total / x.total.sum() * 100
        x["pkt"] = x.rx_bytes / x.rx_pkts.where(x.rx_pkts > 0)
        cols = ["interface"] + [c for c in ("ipsec_tunnel", "peer") if c in x.columns and x[c].notna().any()]
        out.append(ctx.h2("Traffic per tunnel interface since boot"))
        tab = x[cols + ["rx_bytes", "tx_bytes", "share", "pkt"]].head(12).rename(columns={
            "ipsec_tunnel": "IPsec tunnel", "rx_bytes": "received", "tx_bytes": "sent", "share": "% of tunnel traffic",
            "pkt": "avg pkt in"})
        widths = {"interface": 2.0, "IPsec tunnel": 4.0, "peer": 3.0, "received": 2.0, "sent": 2.0,
                  "% of tunnel traffic": 2.2, "avg pkt in": 1.8}
        out.append(ctx.table(tab, [widths[c] for c in tab.columns],
                             fmt={"received": lambda v: C.human(v) + "B", "sent": lambda v: C.human(v) + "B",
                                  "% of tunnel traffic": lambda v: f"{v:.0f}%",
                                  "avg pkt in": lambda v: "-" if pd.isna(v) else f"{v:,.0f} B"}))
        top = x.iloc[0]
        nm = f" ({top.ipsec_tunnel})" if "ipsec_tunnel" in x.columns and isinstance(top.get("ipsec_tunnel"), str) else ""
        ctx.find("info", "VPN", f"Busiest tunnel interface: {top.interface}{nm} with {top.share:.0f}% of all tunnel "
                                f"traffic since boot ({C.human(top.rx_bytes)}B received).")

    # --- ESP over time ------------------------------------------------------------------
    if ds.has("dp_counter_rates"):
        r = ds["dp_counter_rates"]
        names = {"flow_tunnel_ipsec_esp_decap": "decrypted (in)", "flow_tunnel_ipsec_esp_encap": "encrypted (out)"}
        r = r[r.name.isin(names)]
        if not r.empty and r.ts.nunique() >= 3 and r.rate.max() > 0:
            w = r.pivot_table(index="ts", columns="name", values="rate").sort_index().rename(columns=names)
            span = (w.index.max() - w.index.min()).total_seconds() / 86400
            cmap = C.colors_for(list(w.columns))
            f, ax = C.fig(C.W, 2.3)
            for col in w.columns:
                ax.plot(w.index, w[col], color=cmap[col], lw=1.1, label=col)
            ax.set_ylabel("ESP packets / s")
            ax.yaxis.set_major_formatter(C.plt.FuncFormatter(lambda v, _p: C.human(v)))
            ax.set_title("IPsec packets per second over time")
            C.time_axis(ax, span)
            C.legend_below(ax, 2)
            out.append(ctx.figure(f, "vpn_esp_time"))

    # --- CPU share ----------------------------------------------------------------------
    if ds.has("pow_boot"):
        pb = ds["pow_boot"]
        fn = pb[(pb.kind == "func") & ~pb.name.str.contains(K.NOT_CPU)]
        tot = fn.ac_total_us.sum()
        ip = fn[fn.name.str.startswith("tunnel_")]
        if tot > 0 and ip.ac_total_us.sum() > 0:
            share = ip.ac_total_us.sum() / tot * 100
            parts = ip.assign(s=ip.ac_total_us / tot * 100).sort_values("s", ascending=False).head(5)
            out.append(ctx.p(f"<b>Dataplane CPU for IPsec since boot:</b> {share:.1f}% of the tracked function time ("
                             + ", ".join(f"{n} {v:.1f}%" for n, v in zip(parts.name, parts.s)) + ")."))
            ctx.find("info", "VPN", f"IPsec uses {share:.1f}% of the tracked dataplane function time since boot.")
    return out
