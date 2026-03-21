"""Asset management CLI commands."""
import click
from ..api_client import api
from ..formatters import Formatters

SEVERITY_COLORS = {
    "critical": "red",
    "high": "yellow",
    "medium": "cyan",
    "low": "green",
}


@click.group("assets")
def assets_group() -> None:
    """Asset management commands."""
    pass


@assets_group.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
def list_assets(fmt: str) -> None:
    """List all registered assets."""
    response = api.get("/assets")
    if response.status_code != 200:
        Formatters.error(f"Failed to fetch assets: {response.status_code}")
        return

    assets = response.json()

    if fmt == "json":
        Formatters.json_output(assets)
    elif fmt == "csv":
        headers = ["id", "hostname", "ip_address", "asset_type", "criticality", "created_at"]
        Formatters.csv_output(assets, headers)
    else:
        rows = [
            [a.get("id"), a.get("hostname"), a.get("ip_address"), a.get("asset_type"), a.get("criticality")]
            for a in assets
        ]
        Formatters.table(rows, headers=["ID", "Hostname", "IP Address", "Type", "Criticality"], title=f"Assets ({len(assets)})")


@assets_group.command("create")
@click.option("--hostname", prompt="Hostname")
@click.option("--ip", prompt="IP Address")
@click.option("--type", "asset_type", default="server", prompt="Asset Type")
@click.option("--criticality", default="medium", prompt="Criticality (low/medium/high/critical)")
def create_asset(hostname: str, ip: str, asset_type: str, criticality: str) -> None:
    """Register a new asset."""
    response = api.post("/assets", json={
        "hostname": hostname,
        "ip_address": ip,
        "asset_type": asset_type,
        "criticality": criticality,
    })
    if response.status_code in [200, 201]:
        asset = response.json()
        Formatters.success(f"Asset created: [bold]{asset['hostname']}[/bold] ({asset['ip_address']}) ID={asset['id']}")
    else:
        Formatters.error(f"Failed to create asset: {response.status_code} {response.text}")


@assets_group.command("delete")
@click.option("--id", "asset_id", type=int, required=True, prompt="Asset ID")
def delete_asset(asset_id: int) -> None:
    """Delete an asset by ID."""
    if click.confirm(f"Delete asset {asset_id}?"):
        response = api.delete(f"/assets/{asset_id}")
        if response.status_code == 200:
            Formatters.success(f"Asset {asset_id} deleted.")
        else:
            Formatters.error(f"Failed: {response.status_code} {response.text}")
    else:
        Formatters.warn("Aborted.")


@assets_group.command("show")
@click.argument("asset_id", type=int)
def show_asset(asset_id: int) -> None:
    """Show details for a specific asset."""
    response = api.get(f"/assets/{asset_id}")
    if response.status_code == 200:
        asset = response.json()
        rows = [[k, str(v)] for k, v in asset.items()]
        Formatters.table(rows, headers=["Field", "Value"], title=f"Asset {asset_id}")
    else:
        Formatters.error(f"Asset {asset_id} not found.")
