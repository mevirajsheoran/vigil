"""
First-run setup — creates the default organization.

On the very first startup, the organizations table is empty.
We need at least one organization for the app to work
(every request, fingerprint, and attack session has an org_id).

This function checks if the default org exists. If not,
it creates one. If it already exists, it does nothing.
This means it's safe to call on every startup.
"""

from sqlalchemy import select

from Vigil.db.models import Organization, DEFAULT_ORG_ID
from Vigil.db.engine import async_session
from Vigil.config import logger


async def ensure_default_organization() -> None:
    """Create the default organization if it doesn't exist."""
    async with async_session() as session:
        result = await session.execute(
            select(Organization).where(
                Organization.id == DEFAULT_ORG_ID
            )
        )
        org = result.scalar_one_or_none()

        if not org:
            org = Organization(
                id=DEFAULT_ORG_ID,
                name="default",
                plan="free",
            )
            session.add(org)
            await session.commit()
            logger.info("Default organization created")
        else:
            logger.info("Default organization exists")