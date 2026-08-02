"""Render an audit as one self-contained HTML file.

The terminal report answers "what is wrong here" for the person who ran it. This
answers "what is wrong here" for the person they forward it to - a housemate, a
landlord, whoever actually administers the router. That reader will not run the
tool, so the file has to carry the whole lesson with it: no server, no assets, no
network. One file, opened by double-clicking it.

Progressive disclosure is `<details>`/`<summary>`, which every browser has
implemented for a decade. Scripted show/hide would be a dependency, a bug
surface, and a thing that breaks when the file is emailed through something that
strips scripts. The same ladder as the terminal: headline collapsed, the lesson
one click away.

Everything interpolated here comes off the network - device names, banners, mDNS
labels, a router's own description of a port forward. This module is where that
becomes markup, so `esc()` is not a formality: it is the same class of hole as
the shell injection in the `verify` commands, one language over. Nothing reaches
the page except through it.
"""

from __future__ import annotations

from html import escape

from .audit import SEVERITY_ORDER, headline

# Deliberately drab. A report that looks like a security product invites the
# reader to skim the colours instead of the sentences, and the whole thesis here
# is that the sentences are the product.
STYLE = """
:root { color-scheme: light dark; }
body { font: 16px/1.6 system-ui, -apple-system, Segoe UI, sans-serif;
       max-width: 46rem; margin: 3rem auto; padding: 0 1.25rem; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.sub { opacity: .7; font-size: .9rem; margin: 0 0 2rem; }
details { border-top: 1px solid rgba(128,128,128,.3); padding: .7rem 0; }
details:last-of-type { border-bottom: 1px solid rgba(128,128,128,.3); }
summary { cursor: pointer; display: flex; gap: .7rem; align-items: baseline; }
summary::marker { color: rgba(128,128,128,.7); }
.sev { flex: none; font-size: .72rem; letter-spacing: .06em;
       text-transform: uppercase; padding: .1rem .45rem; border-radius: .2rem;
       border: 1px solid currentColor; opacity: .85; }
.critical, .high { color: #c0392b; }
.medium { color: #b9770e; }
.info { color: #5d6d7e; }
.new { flex: none; font-size: .7rem; font-weight: 600; letter-spacing: .06em; }
dl { margin: .9rem 0 .3rem; }
dt { font-size: .72rem; letter-spacing: .06em; text-transform: uppercase;
     opacity: .6; margin-top: .9rem; }
dd { margin: .2rem 0 0; }
pre { white-space: pre-wrap; word-break: break-word; background: rgba(128,128,128,.12);
      padding: .6rem .75rem; border-radius: .25rem; font-size: .85rem; margin: .2rem 0 0; }
footer { margin-top: 2.5rem; font-size: .85rem; opacity: .7; }
"""

FIELDS = (
    ("evidence", "what was observed", True),
    ("why", "why it matters", False),
    ("fix", "how to fix it", False),
    ("verify", "confirm it yourself", True),
)


def esc(value) -> str:
    """Everything on this page came off the network. Nothing skips this."""
    return escape(str(value), quote=True)


def _finding_html(finding, is_new: bool) -> str:
    rows = []
    for name, label, preformatted in FIELDS:
        text = esc(getattr(finding, name))
        body = f"<pre>{text}</pre>" if preformatted else f"<p>{text}</p>"
        rows.append(f"<dt>{label}</dt><dd>{body}</dd>")
    new = '<span class="new">NEW</span>' if is_new else ""
    return (
        "<details>"
        f'<summary><span class="sev {esc(finding.severity)}">'
        f"{esc(finding.severity)}</span>"
        f"<span>{esc(headline(finding))}</span>{new}</summary>"
        f"<dl>{''.join(rows)}</dl>"
        "</details>"
    )


def render(annotated, subnet: str, scan_id: int, started: str, summary: str) -> str:
    """One HTML document for an audit.

    `annotated` is the (finding, is_new) list the terminal report renders, so
    both views are fed by the same thing and cannot drift apart.
    """
    findings = sorted(
        annotated, key=lambda pair: (SEVERITY_ORDER[pair[0].severity], pair[0].device)
    )
    body = "".join(_finding_html(f, is_new) for f, is_new in findings) or (
        "<p>Nothing to report - no devices answered, or none had open ports.</p>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>netdiff audit {esc(scan_id)} - {esc(subnet)}</title>"
        f"<style>{STYLE}</style></head><body>"
        f"<h1>{esc(subnet)} - {esc(summary)}</h1>"
        f'<p class="sub">audit {esc(scan_id)}, {esc(started)}. '
        "Click any finding for the evidence it rests on, why it matters, how to "
        "fix it, and a command you can run yourself to confirm it.</p>"
        f"{body}"
        "<footer>An open port is not a vulnerability - it is what a working "
        "device looks like. Only the findings above are claims about this "
        "network, and each one quotes the observation that produced it. "
        "Do not take a scanner's word for anything, including this one.</footer>"
        "</body></html>\n"
    )
