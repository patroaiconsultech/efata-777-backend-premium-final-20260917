"""AO-01 focus: existing REST POST viewer guards, without altering production patch."""
import asyncio
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from orkio_v2.auth import Principal
from orkio_v2.models import Base, Tenant, User, Thread, ThreadParticipant
from orkio_v2.routes import MessageCreate, send_message, stream_message

@pytest.mark.parametrize("handler", [send_message, stream_message])
def test_viewer_cannot_post(handler):
    engine=create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine,tables=[Tenant.__table__,User.__table__,Thread.__table__,ThreadParticipant.__table__])
    with Session(engine) as db:
        db.add_all([Tenant(id="t1",name="t1"),User(id="u1",external_subject="u1",email="u1@invalid.test",display_name="U1"),Thread(id="th1",tenant_id="t1",created_by="u1"),ThreadParticipant(id="p1",tenant_id="t1",thread_id="th1",user_id="u1",active=True,thread_role="viewer",history_access="full_thread",joined_at=datetime.now(timezone.utc))]);db.commit()
        async def invoke():
            return await handler("th1",MessageCreate(content="hi"),p=Principal(user_id="u1",tenant_id="t1",roles=("member",)),settings=object(),db=db)
        with pytest.raises(HTTPException) as exc:
            asyncio.run(invoke())
        assert exc.value.status_code == 403
        assert exc.value.detail == "THREAD_READ_ONLY"
