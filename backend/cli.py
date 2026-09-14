#!/usr/bin/env python3
import asyncio
import sys
import uuid
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from app.orchestrator.orchestrator import orchestrator
from app.events.event_bus import event_bus
from app.events.events import EventType

app = typer.Typer(help="AegisPentest: Autonomous AI Security Testing Platform CLI")
console = Console()

@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or local directory path"),
    mode: str = typer.Option("black_box", "--mode", "-m", help="Assessment mode: black_box, grey_box, white_box"),
    instruction: str = typer.Option("", "--instruction", "-i", help="Specific testing guidance or focus area"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file path")
):
    """
    Launch an autonomous security assessment against an authorized target.
    """
    asyncio.run(run_scan_async(target, mode, instruction, output))

async def run_scan_async(target: str, mode: str, instruction: str, output_file: Optional[str]):
    scan_id = str(uuid.uuid4())
    
    console.print(Panel.fit(
        f"[bold cyan]AegisPentest Autonomous Security Assessment[/bold cyan]\n"
        f"[bold]Scan ID:[/bold] {scan_id}\n"
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Mode:[/bold] {mode}\n"
        f"[bold]Scope Enforced:[/bold] Strict Pre-Flight Checks Active",
        border_style="cyan"
    ))

    queue = event_bus.subscribe_scan(scan_id)
    
    # Start scan in background
    scan_task = asyncio.create_task(orchestrator.start_scan(
        scan_id=scan_id,
        target=target,
        mode=mode,
        instruction=instruction
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        overall_task = progress.add_task("[yellow]Initializing Root Orchestrator...", total=None)

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=2.0)
                payload = event.payload
                
                if event.event_type == EventType.AGENT_CREATED:
                    role = payload.get("role", "Agent")
                    progress.update(overall_task, description=f"[cyan]Spawned sub-agent: {role}")
                elif event.event_type == EventType.TOOL_STARTED:
                    tool = payload.get("tool_name")
                    progress.update(overall_task, description=f"[dim]Executing tool {tool}...")
                elif event.event_type == EventType.ENDPOINT_DISCOVERED:
                    url = payload.get("url")
                    console.print(f"  [green]+ Discovered endpoint:[/green] {url}")
                elif event.event_type == EventType.FINDING_VALIDATED:
                    f = payload.get("finding", {})
                    console.print(f"  [bold red]✔ [CONFIRMED VULNERABILITY]:[/bold red] [{f.get('severity','').upper()}] {f.get('title')} ({f.get('cwe')})")
                elif event.event_type == EventType.SCAN_COMPLETED:
                    progress.update(overall_task, description="[bold green]Scan Completed!")
                    break
            except asyncio.TimeoutError:
                if scan_task.done():
                    break

    await scan_task
    state = orchestrator.get_state(scan_id)
    if state:
        console.print("\n")
        table = Table(title="Security Assessment Findings Summary", border_style="red")
        table.add_column("Severity", style="bold")
        table.add_column("Vulnerability Title")
        table.add_column("CWE")
        table.add_column("Affected Endpoint / Asset")
        table.add_column("Validation Status", style="green")

        for f in state.validated_findings:
            table.add_row(
                f.severity.upper(),
                f.title,
                f.cwe,
                f.affected_endpoint or f.affected_asset,
                "VERIFIED PoC"
            )

        console.print(table)
        console.print(f"\n[bold green]Assessment finished.[/bold green] Total Verified Findings: {len(state.validated_findings)}\n")

if __name__ == "__main__":
    app()
