import json
from datetime import datetime
from db import SessionLocal, Asset, Vulnerability, Owner, create_tables
 
 
def migrate():
 
    # ── Step 1: Load JSON data ─────────────────────────────────────────────
    print("📂 Loading assets_v2.json...")
 
    with open("data/assets_v2.json", "r") as f:
        assets_data = json.load(f)
 
    print(f"   Found {len(assets_data)} assets to migrate")
 
    # ── Step 2: Open a database session ───────────────────────────────────
    db = SessionLocal()
 
    try:
 
        # ── Step 3: Clear existing data ────────────────────────────────────
        # Delete in this order due to foreign key constraints:
        # vulnerabilities and owners reference assets,
        # so they must be deleted BEFORE assets
        print("\n🗑️  Clearing existing data...")
        db.query(Vulnerability).delete()
        db.query(Owner).delete()
        db.query(Asset).delete()
        db.commit()
        print("   Cleared: assets, vulnerabilities, owners")
 
        # ── Step 4: Insert each asset ──────────────────────────────────────
        print("\n🔄 Migrating assets...")
 
        asset_count = 0
        vuln_count  = 0
        owner_count = 0
 
        for asset_data in assets_data:
 
            # ── 4a: Parse last_scan_date ───────────────────────────────────
            # JSON stores dates as strings "2026-01-04"
            # Convert to Python date objects for PostgreSQL
            last_scan = None
            if asset_data.get("last_scan_date"):
                try:
                    last_scan = datetime.strptime(
                        asset_data["last_scan_date"], "%Y-%m-%d"
                    ).date()
                except ValueError:
                    last_scan = None
 
            # ── 4b: Create the Asset record ────────────────────────────────
            asset = Asset(
                asset_id         = asset_data["asset_id"],
                asset_type       = asset_data["asset_type"],
                environment      = asset_data["environment"],
                criticality      = asset_data["criticality"],
                ip_address       = asset_data.get("ip_address"),
                domain           = asset_data.get("domain"),
                internet_exposed = asset_data.get("internet_exposed", False),
                os_name          = asset_data.get("os", {}).get("name"),
                os_version       = asset_data.get("os", {}).get("version"),
                software_name    = asset_data.get("software", {}).get("name"),
                software_version = asset_data.get("software", {}).get("version"),
                risk_score       = asset_data.get("risk_score"),
                risk_level       = (
                    "Critical" if asset_data.get("risk_score", 0) >= 80 else
                    "High"     if asset_data.get("risk_score", 0) >= 60 else
                    "Medium"   if asset_data.get("risk_score", 0) >= 40 else
                    "Low"
                ),
                last_scan_date   = last_scan,
            )
 
            db.add(asset)
            asset_count += 1
 
            # ── 4c: Create Vulnerability records ───────────────────────────
            # One Vulnerability row per CVE per asset
            for vuln_data in asset_data.get("vulnerabilities", []):
                vuln = Vulnerability(
                    asset_id          = asset_data["asset_id"],
                    cve               = vuln_data.get("cve", "UNKNOWN"),
                    severity          = vuln_data.get("severity", "Unknown"),
                    cvss_score        = vuln_data.get("cvss_score"),
                    exploit_available = vuln_data.get("exploit_available", False),
                    patch_available   = vuln_data.get("patch_available", False),
                    description       = vuln_data.get("description", ""),
                )
                db.add(vuln)
                vuln_count += 1
 
            # ── 4d: Create Owner record ────────────────────────────────────
            # Every asset has exactly one owner record
            owner_info = asset_data.get("owner", {})
            owner = Owner(
                asset_id = asset_data["asset_id"],
                team     = owner_info.get("team"),
                email    = owner_info.get("email"),
                status   = owner_info.get("status", "assigned"),
            )
            db.add(owner)
            owner_count += 1
 
            if asset_count % 10 == 0:
                print(f"   Processed {asset_count}/{len(assets_data)} assets...",
                      end="\r")
 
        # ── Step 5: Commit everything to Supabase ──────────────────────────
        # Until now everything was staged in memory
        # commit() sends all inserts to PostgreSQL in one transaction
        print(f"\n   Processed {asset_count}/{len(assets_data)} assets...")
        print("\n💾 Committing to Supabase...")
        db.commit()
 
        # ── Step 6: Summary ────────────────────────────────────────────────
        print("\n✅ Migration complete!")
        print(f"   Assets inserted         : {asset_count}")
        print(f"   Vulnerabilities inserted : {vuln_count}")
        print(f"   Owner records inserted   : {owner_count}")
 
        # ── Step 7: Verify by querying back from Supabase ──────────────────
        print("\n🔍 Verifying migration...")
 
        total_assets = db.query(Asset).count()
        total_vulns  = db.query(Vulnerability).count()
        total_owners = db.query(Owner).count()
        orphans      = db.query(Owner).filter(Owner.status == "orphan").count()
        exposed      = db.query(Asset).filter(Asset.internet_exposed == True).count()
        critical     = db.query(Asset).filter(Asset.risk_level == "Critical").count()
 
        print(f"\n📊 Supabase now contains:")
        print(f"   Total assets         : {total_assets}")
        print(f"   Total CVEs           : {total_vulns}")
        print(f"   Total owner records  : {total_owners}")
        print(f"   Orphan assets        : {orphans}")
        print(f"   Internet-exposed     : {exposed}")
        print(f"   Critical risk assets : {critical}")
 
    except Exception as e:
        # Roll back ALL changes if anything fails
        db.rollback()
        print(f"\n❌ Migration failed: {e}")
        raise e
 
    finally:
        db.close()
 
 
if __name__ == "__main__":
    print("🚀 Sentinel — Database Migration")
    print("=" * 40)
    create_tables()
    migrate()