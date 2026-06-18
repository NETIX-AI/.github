#!/usr/bin/env python3
"""Org-wide Dependabot alert digest + SLA escalation, delivered by email.

Triggered by .github/workflows/dependabot-alert-digest.yml. Stateless: every run
re-queries the org-level Dependabot alerts API and reports the live picture, so
there is no state file to drift. Two modes (selected by the workflow via $MODE):

  daily : full digest of all open alerts, grouped by severity, with any alert
          past its remediation SLA highlighted at the top.
  new   : urgent path -- emails ONLY if a high/critical alert was opened within
          the last $WINDOW_HOURS hours (keeps "raised quickly" without spam).

No merging or mutation happens here -- humans still review and merge every fix
(SOC2 change-management is preserved). This job only surfaces and escalates.
"""
import datetime as dt
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from email.mime.text import MIMEText

ORG = os.environ.get("ORG", "NETIX-AI")
TOKEN = os.environ["SECURITY_ALERTS_TOKEN"]
MODE = os.environ.get("MODE", "daily")
WINDOW_HOURS = int(os.environ.get("WINDOW_HOURS", "6"))

# Strict remediation SLA in days -- Critical 3 / High 7 / Medium 14 / Low 30.
SLA = {"critical": 3, "high": 7, "medium": 14, "low": 30}
SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLOR = {"critical": "#b30000", "high": "#d9534f",
             "medium": "#e0a800", "low": "#6c757d"}


def api(url):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    return urllib.request.urlopen(req, timeout=30)


def fetch_alerts():
    # The org Dependabot alerts endpoint uses cursor pagination via the Link
    # header (the `page` param is rejected), so follow rel="next" until exhausted.
    url = f"https://api.github.com/orgs/{ORG}/dependabot/alerts?state=open&per_page=100"
    alerts = []
    while url:
        with api(url) as resp:
            alerts.extend(json.load(resp))
            link = resp.headers.get("Link", "")
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None
    return alerts


def to_rows(alerts, now):
    rows = []
    for a in alerts:
        adv = a["security_advisory"]
        sev = adv["severity"]
        created = dt.datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))
        age_days = (now - created).days
        rows.append({
            "repo": a["repository"]["name"],
            "pkg": a["dependency"]["package"]["name"],
            "eco": a["dependency"]["package"]["ecosystem"],
            "sev": sev,
            "id": adv.get("cve_id") or adv["ghsa_id"],
            "summary": (adv["summary"] or "")[:120],
            "age": age_days,
            "url": a["html_url"],
            "breach": age_days > SLA.get(sev, 10 ** 9),
            "fresh": (now - created).total_seconds() <= WINDOW_HOURS * 3600,
        })
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    rows.sort(key=lambda r: (sev_rank.get(r["sev"], 9), -r["age"]))
    return rows


def table(rows):
    head = ("<tr style='text-align:left'><th>Severity</th><th>Repo</th>"
            "<th>Package</th><th>Advisory</th><th>Age</th><th>SLA</th></tr>")
    out = []
    for r in rows:
        sla = SLA.get(r["sev"], "-")
        flag = (f"<b style='color:#b30000'>BREACH (&gt;{sla}d)</b>"
                if r["breach"] else f"{sla}d")
        fresh = " <span style='color:#0a7'>&#9679;NEW</span>" if r["fresh"] else ""
        out.append(
            f"<tr>"
            f"<td style='color:{SEV_COLOR.get(r['sev'], '#000')}'><b>{r['sev']}</b></td>"
            f"<td>{r['repo']}{fresh}</td>"
            f"<td>{r['pkg']} <span style='color:#888'>({r['eco']})</span></td>"
            f"<td><a href='{r['url']}'>{r['id']}</a><br>"
            f"<span style='color:#555;font-size:12px'>{r['summary']}</span></td>"
            f"<td>{r['age']}d</td><td>{flag}</td></tr>")
    return f"<table cellpadding=6 style='border-collapse:collapse;font-family:sans-serif;font-size:14px'>{head}{''.join(out)}</table>"


def render_daily(rows, now):
    counts = {s: sum(1 for r in rows if r["sev"] == s) for s in SEV_ORDER}
    breaches = [r for r in rows if r["breach"]]
    summary = " &nbsp;|&nbsp; ".join(
        f"<b style='color:{SEV_COLOR[s]}'>{counts[s]} {s}</b>" for s in SEV_ORDER)
    parts = [f"<h2>Dependabot digest &mdash; {ORG}</h2>",
             f"<p>{len(rows)} open alerts as of {now:%Y-%m-%d %H:%M UTC}<br>{summary}</p>"]
    if breaches:
        parts.append("<h3 style='color:#b30000'>&#9888; Past SLA &mdash; "
                     f"remediate now ({len(breaches)})</h3>")
        parts.append(table(breaches))
    parts.append("<h3>All open alerts</h3>")
    parts.append(table(rows))
    parts.append("<p style='color:#888;font-size:12px'>Strict SLA: Critical 3d / "
                 "High 7d / Medium 14d / Low 30d. Fixes are merged by a human after "
                 "review &mdash; this digest only surfaces and escalates.</p>")
    subj = (f"[{ORG}] Dependabot: {len(rows)} open "
            f"({counts['critical']}C/{counts['high']}H) — {len(breaches)} past SLA")
    return subj, "".join(parts)


def render_new(rows, now):
    focus = [r for r in rows if r["fresh"] and r["sev"] in ("critical", "high")]
    if not focus:
        return None, None
    subj = f"[{ORG}] ⚠ {len(focus)} new high/critical Dependabot alert(s)"
    body = (f"<h2 style='color:#b30000'>&#9888; New high/critical alerts "
            f"(last {WINDOW_HOURS}h)</h2>{table(focus)}")
    return subj, body


def send(subject, html):
    to = os.environ["ALERT_RECIPIENTS"]
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = os.environ.get("MAIL_FROM", os.environ["SMTP_USERNAME"])
    msg["To"] = to
    if os.environ.get("DRY_RUN") == "1":
        print("DRY_RUN -- not sending. Subject:", subject)
        print(html[:800])
        return
    host = os.environ.get("SMTP_SERVER", "smtp.office365.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls(context=ctx)
        s.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        s.sendmail(msg["From"], [a.strip() for a in to.split(",")], msg.as_string())
    print("Sent:", subject)


def main():
    now = dt.datetime.now(dt.timezone.utc)
    rows = to_rows(fetch_alerts(), now)
    if MODE == "new":
        subject, html = render_new(rows, now)
        if subject is None:
            print(f"No new high/critical alerts in the last {WINDOW_HOURS}h; nothing to send.")
            return
    else:
        subject, html = render_daily(rows, now)
    send(subject, html)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        print(f"GitHub API error {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
        sys.exit(1)
