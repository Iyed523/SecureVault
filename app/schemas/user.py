from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class PublicUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    is_active: bool
    created_at: datetime
