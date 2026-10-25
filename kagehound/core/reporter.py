"""
Reporting and alert dispatch engine for KageHound.
Supports Rich CLI tables, JSON export, SARIF v2.1.0 generation, and Telegram notifications.
"""

import json

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from kagehound.core.models import (
    BreachMatch,
    LeakMatch,
    SecretMatch,
    Severity,
    VerificationStatus,
)

console = Console()


def print_banner() -> None:
    """Print KageHound banner in terminal."""
    banner_text = Text()
    banner_text.append("🛡️  KageHound", style="bold cyan")
    banner_text.append(
        " | Unified Secret Defense & Threat Intelligence Suite\n", style="bold white"
    )
    banner_text.append("Shadow Protection & Zero-Knowledge Leak Radar", style="dim white")
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def display_scan_results(
    matches: list[SecretMatch],
    total_files: int,
    elapsed_seconds: float,
) -> None:
    """Render Rich CLI table for secret scan findings."""
    if not matches:
        console.print(
            Panel(
                Text("✨ No secret leaks detected! Your workspace is clean.", style="bold green"),
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"🚨 Secret Leaks Detected ({len(matches)} findings)",
        border_style="red",
        header_style="bold magenta",
    )
    table.add_column("Rule", style="bold white")
    table.add_column("Severity", justify="center")
    table.add_column("Location", style="cyan")
    table.add_column("Redacted Secret", style="yellow")
    table.add_column("Verification", justify="center")
    table.add_column("Entropy", justify="right")

    for m in matches:
        # Severity styling
        if m.severity == Severity.CRITICAL:
            sev_text = Text("CRITICAL", style="bold white on red")
        elif m.severity == Severity.HIGH:
            sev_text = Text("HIGH", style="bold red")
        elif m.severity == Severity.MEDIUM:
            sev_text = Text("MEDIUM", style="yellow")
        else:
            sev_text = Text("LOW", style="blue")

        # Verification styling
        v_status = m.verification.status
        if v_status == VerificationStatus.ACTIVE:
            ver_text = Text("⚡ ACTIVE", style="bold white on red")
        elif v_status == VerificationStatus.INACTIVE:
            ver_text = Text("💀 DEAD", style="dim green")
        elif v_status == VerificationStatus.UNVERIFIABLE:
            ver_text = Text("❓ UNVERIFIED", style="dim")
        else:
            ver_text = Text("-", style="dim")

        loc = f"{m.file_path}:{m.line_number}"
        ent = f"{m.entropy:.2f}" if m.entropy is not None else "-"

        table.add_row(
            m.rule_name,
            sev_text,
            loc,
            m.redacted_secret,
            ver_text,
            ent,
        )

    console.print(table)

    # Summary Panel
    active_count = sum(1 for m in matches if m.verification.status == VerificationStatus.ACTIVE)
    summary_text = (
        f"[bold]Files Scanned:[/bold] {total_files} | "
        f"[bold]Total Leaks:[/bold] [red]{len(matches)}[/red] | "
        f"[bold]Active Verified Secrets:[/bold] [{'bold red' if active_count > 0 else 'green'}]{active_count}[/] | "
        f"[bold]Duration:[/bold] {elapsed_seconds:.2f}s"
    )
    console.print(Panel(summary_text, border_style="yellow" if active_count == 0 else "red"))


def display_breach_results(breaches: list[BreachMatch]) -> None:
    """Render Rich CLI table for breach radar results."""
    if not breaches:
        console.print("[bold green]✅ No historical breach records found for target.[/bold green]")
        return

    table = Table(
        title=f"⚠️ Global Breach Radar ({len(breaches)} records)",
        border_style="yellow",
        header_style="bold yellow",
    )
    table.add_column("Breach Name", style="bold white")
    table.add_column("Date", style="cyan")
    table.add_column("Exposed Accounts", justify="right", style="magenta")
    table.add_column("Compromised Data", style="dim white")

    for b in breaches:
        data_str = ", ".join(b.data_classes[:4])
        if len(b.data_classes) > 4:
            data_str += f" (+{len(b.data_classes) - 4} more)"
        table.add_row(
            b.breach_name,
            b.breach_date or "Unknown",
            f"{b.pwn_count:,}",
            data_str or b.description[:50],
        )
    console.print(table)


def display_darkweb_results(matches: list[LeakMatch]) -> None:
    """Render Rich CLI table for dark web and paste intelligence findings."""
    if not matches:
        console.print("[bold green]✅ No dark web or paste leaks found for target.[/bold green]")
        return

    table = Table(
        title=f"🕷️ Dark Web & Paste Intelligence ({len(matches)} exposures)",
        border_style="red",
        header_style="bold red",
    )
    table.add_column("Source", style="bold cyan")
    table.add_column("Title / URL", style="yellow")
    table.add_column("Snippet Preview", style="dim white")

    for m in matches:
        snippet = m.snippet.replace("\n", " ")[:80] if m.snippet else "-"
        table.add_row(
            m.source.upper(),
            f"{m.title}\n[dim]{m.url}[/dim]",
            snippet,
        )
    console.print(table)


def export_json(matches: list[SecretMatch], output_path: str) -> None:
    """Export scan results to structured JSON."""
    data = [m.model_dump() for m in matches]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim green]Exported JSON report to {output_path}[/dim green]")


def export_sarif(matches: list[SecretMatch], output_path: str) -> None:
    """Export scan results in OASIS SARIF v2.1.0 format."""
    rules_dict = {}
    results = []

    for idx, m in enumerate(matches):
        if m.rule_id not in rules_dict:
            rules_dict[m.rule_id] = {
                "id": m.rule_id,
                "name": m.rule_name,
                "shortDescription": {"text": m.rule_name},
                "defaultConfiguration": {
                    "level": "error"
                    if m.severity in [Severity.CRITICAL, Severity.HIGH]
                    else "warning"
                },
            }

        results.append(
            {
                "ruleId": m.rule_id,
                "ruleIndex": list(rules_dict.keys()).index(m.rule_id),
                "message": {"text": f"Secret leak detected: {m.rule_name} ({m.redacted_secret})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": m.file_path},
                            "region": {"startLine": m.line_number},
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "KageHound",
                        "version": "1.0.0",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2)
    console.print(f"[dim green]Exported SARIF report to {output_path}[/dim green]")


def dispatch_telegram_alert(
    bot_token: str | None,
    chat_id: str | None,
    matches: list[SecretMatch],
) -> bool:
    """
    Send high-priority mobile alert via Telegram Bot API.
    All secrets are strictly redacted before sending.
    """
    if not bot_token or not chat_id:
        return False

    if not matches:
        return True

    active_count = sum(1 for m in matches if m.verification.status == VerificationStatus.ACTIVE)
    title = "🚨 *KAGEVIGIL ALERT: SECRET LEAK DETECTED!*"
    if active_count > 0:
        title = f"🔥 *CRITICAL: {active_count} ACTIVE CREDENTIALS LEAKED!*"

    lines = [
        title,
        f"Detected *{len(matches)}* secret leak(s) across workspace.",
        "",
        "*Top Findings:*",
    ]

    for m in matches[:5]:
        v_badge = " [ACTIVE]" if m.verification.status == VerificationStatus.ACTIVE else ""
        lines.append(f"• *{m.rule_name}*{v_badge}: `{m.file_path}:{m.line_number}`")
        lines.append(f"  Token: `{m.redacted_secret}`")

    if len(matches) > 5:
        lines.append(f"...and {len(matches) - 5} more.")

    lines.append("")
    lines.append("⚡ *Action Required:* Rotate compromised secrets immediately.")

    text = "\n".join(lines)

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    try:
        res = requests.post(url, json=payload, timeout=10)
        return res.status_code == 200
    except Exception:
        return False
