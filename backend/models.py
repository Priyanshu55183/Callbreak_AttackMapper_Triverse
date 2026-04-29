# models.py has been consolidated into db.py
# Import UserRole and other models from db.py
from db import UserRole, Asset, Vulnerability, Owner, Base

__all__ = ["UserRole", "Asset", "Vulnerability", "Owner", "Base"]