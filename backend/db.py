import os
from dotenv import load_dotenv
 
from sqlalchemy import (
    create_engine,        # creates the connection to PostgreSQL
    Column,               # defines a column in a table
    String,               # text column type
    Float,                # decimal number column type
    Boolean,              # true/false column type
    Integer,              # whole number column type
    Text,                 # long text column type
    DateTime,             # date + time column type
    Date,                 # date only column type
    ForeignKey,           # links one table to another
)
from sqlalchemy.dialects.postgresql import UUID
import uuid
from sqlalchemy.orm import (
    declarative_base,     # base class all models inherit from
    sessionmaker,         # creates database sessions
    relationship,         # defines relationships between tables
)
from sqlalchemy.sql import func  # for SQL functions like NOW()
 

load_dotenv()
 

DATABASE_URL = os.getenv("DATABASE_URL")
 
if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL not found in .env file. "
        "Please add: DATABASE_URL=postgresql://postgres:password@..."
    )
 

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)
 

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)
 

Base = declarative_base()
 
 

 
class Asset(Base):
    """
    Represents one row in the 'assets' table.
    Each asset is a digital component in the organization's infrastructure.
    """
    __tablename__ = "assets"  # this is the actual table name in PostgreSQL
 
    # Primary key — auto-increments for each new asset
    id = Column(Integer, primary_key=True, autoincrement=True)
 
    # Unique human-readable asset identifier e.g. "ASSET-1000"
    asset_id = Column(String(50), unique=True, nullable=False, index=True)
 
    # Type of asset e.g. "Web Server", "Database Server", "Cloud VM"
    asset_type = Column(String(100), nullable=False)
 
    # Which environment this asset lives in
    environment = Column(String(50), nullable=False)  # Production / Staging / Development
 
    # How important this asset is to the business
    criticality = Column(String(20), nullable=False)  # Low / Medium / High
 
    # Network details
    ip_address = Column(String(45), nullable=True)    # supports IPv4 and IPv6
    domain     = Column(String(255), nullable=True)
 
    # Whether this asset is reachable from the public internet
    internet_exposed = Column(Boolean, default=False)
 
    # Operating system details
    os_name    = Column(String(100), nullable=True)   # e.g. "Ubuntu"
    os_version = Column(String(50),  nullable=True)   # e.g. "22.04"
 
    # Software running on this asset
    software_name    = Column(String(100), nullable=True)  # e.g. "nginx"
    software_version = Column(String(50),  nullable=True)  # e.g. "1.18.0"
 
    # ML-computed risk fields (set after ML scoring runs)
    risk_score = Column(Float,       nullable=True)   # 0.0 to 100.0
    risk_level = Column(String(20),  nullable=True)   # Critical / High / Medium / Low
 
    # When this asset was last security scanned
    last_scan_date = Column(Date, nullable=True)
 
    # Automatic timestamps
    created_at = Column(DateTime, server_default=func.now())  # set on INSERT
    updated_at = Column(DateTime, server_default=func.now(),  # set on INSERT
                        onupdate=func.now())                  # updated on UPDATE
 
    # Relationships — tells SQLAlchemy that one Asset has many Vulnerabilities
    # cascade="all, delete-orphan" means if you delete an asset,
    # its vulnerabilities and owner are automatically deleted too
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    owner = relationship(
        "Owner",
        back_populates="asset",
        uselist=False,              # one asset has exactly ONE owner record
        cascade="all, delete-orphan",
    )
 
    def to_dict(self):
        """
        Converts this Asset object into a plain Python dictionary.
        Useful for returning data from FastAPI endpoints as JSON.
        """
        return {
            "asset_id":        self.asset_id,
            "asset_type":      self.asset_type,
            "environment":     self.environment,
            "criticality":     self.criticality,
            "ip_address":      self.ip_address,
            "domain":          self.domain,
            "internet_exposed": self.internet_exposed,
            "os": {
                "name":    self.os_name,
                "version": self.os_version,
            },
            "software": {
                "name":    self.software_name,
                "version": self.software_version,
            },
            "risk_score":      self.risk_score,
            "risk_level":      self.risk_level,
            "last_scan_date":  str(self.last_scan_date) if self.last_scan_date else None,
            "created_at":      str(self.created_at) if self.created_at else None,
            # These are loaded separately to avoid circular references
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "owner":           self.owner.to_dict() if self.owner else None,
        }
 
 
class Vulnerability(Base):
    """
    Represents one CVE linked to one asset.
    One asset can have many vulnerabilities.
    """
    __tablename__ = "vulnerabilities"
 
    id = Column(Integer, primary_key=True, autoincrement=True)
 
    # Foreign key — links this vulnerability to its parent asset
    # If the asset is deleted, this row is deleted too (cascade)
    asset_id = Column(
        String(50),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,   # index makes lookups by asset_id fast
    )
 
    # CVE identifier e.g. "CVE-2021-23017"
    cve = Column(String(50), nullable=False)
 
    # Severity level from the CVE database
    severity = Column(String(20), nullable=False)  # Critical / High / Medium / Low
 
    # CVSS score — industry standard vulnerability severity score (0.0 to 10.0)
    cvss_score = Column(Float, nullable=True)
 
    # Whether a known working exploit exists for this CVE
    exploit_available = Column(Boolean, default=False)
 
    # Whether a patch/fix has been released by the vendor
    patch_available = Column(Boolean, default=False)
 
    # Full description of what this vulnerability does
    description = Column(Text, nullable=True)
 
    # When this CVE was detected on this asset
    detected_at = Column(DateTime, server_default=func.now())
 
    # Relationship back to the parent asset
    asset = relationship("Asset", back_populates="vulnerabilities")
 
    def to_dict(self):
        return {
            "cve":               self.cve,
            "severity":          self.severity,
            "cvss_score":        self.cvss_score,
            "exploit_available": self.exploit_available,
            "patch_available":   self.patch_available,
            "description":       self.description,
            "detected_at":       str(self.detected_at) if self.detected_at else None,
        }
 
 
class Owner(Base):
    """
    Represents the team responsible for securing one asset.
    One asset has exactly one owner record.
    Status is either 'assigned' or 'orphan'.
    """
    __tablename__ = "owners"
 
    id = Column(Integer, primary_key=True, autoincrement=True)
 
    # Foreign key — links this owner record to one asset
    asset_id = Column(
        String(50),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,   # enforces one owner record per asset
        index=True,
    )
 
    # Team name e.g. "DevOps", "Security Ops"
    team  = Column(String(100), nullable=True)  # nullable for orphan assets
 
    # Team contact email
    email = Column(String(255), nullable=True)  # nullable for orphan assets
 
    # Whether this asset has an owner or not
    status = Column(String(20), default="assigned")  # "assigned" or "orphan"
 
    # Timestamp
    assigned_at = Column(DateTime, server_default=func.now())
 
    # Relationship back to the parent asset
    asset = relationship("Asset", back_populates="owner")
 
    def to_dict(self):
        return {
            "team":   self.team,
            "email":  self.email,
            "status": self.status,
        }


class UserRole(Base):
    """
    Maps Supabase authentication user_id to an application role.
    Every authenticated user gets exactly one role: admin, analyst, or viewer.
    This table is the source of truth for role-based access control (RBAC).
    """
    __tablename__ = "user_roles"

    # UUID primary key — same UUID format as Supabase uses for user_id
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Supabase user UUID — link to the authenticated user in Supabase Auth
    # Must be unique because each user should have exactly one role
    user_id = Column(UUID(as_uuid=True), nullable=False, unique=True, index=True)

    # Role assignment: "admin", "analyst", or "viewer"
    # This controls what endpoints and data the user can access
    role = Column(String(20), nullable=False)  # admin / analyst / viewer

    # Email associated with this user (stored for reference)
    email = Column(String(255), nullable=True)

    # When this role was assigned
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # When this role was last updated
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def to_dict(self):
        return {
            "id":         str(self.id),
            "user_id":    str(self.user_id),
            "role":       self.role,
            "email":      self.email,
            "created_at": str(self.created_at) if self.created_at else None,
            "updated_at": str(self.updated_at) if self.updated_at else None,
        }
 
 
# ─── Step 7: Dependency for FastAPI ──────────────────────────────────────────
 
def get_db():
    """
    Creates a database session for one request and closes it when done.
 
    This is used as a FastAPI dependency:
        @app.get("/assets")
        def get_assets(db: Session = Depends(get_db)):
            ...
 
    The 'yield' makes it a generator:
      - Everything before yield runs BEFORE the endpoint
      - Everything after yield runs AFTER the endpoint (cleanup)
    """
    db = SessionLocal()
    try:
        yield db          # hand the session to the endpoint
    finally:
        db.close()        # always close, even if an error occurred
 
 
# ─── Step 8: Create all tables ───────────────────────────────────────────────
 
def create_tables():
    """
    Creates all tables in your Supabase PostgreSQL database.
    Safe to run multiple times — only creates tables that don't exist yet.
    """
    Base.metadata.create_all(bind=engine)
    print("✅ All tables created successfully in Supabase!")
    print("   Tables: assets, vulnerabilities, owners, user_roles")
 
 
# ─── Run directly to create tables ───────────────────────────────────────────
# When you run: python db.py
# It will create all three tables in your Supabase database
 
if __name__ == "__main__":
    print("🔄 Connecting to Supabase PostgreSQL...")
    create_tables()