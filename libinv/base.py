# base class declared
import sqlalchemy as db
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from libinv.env import DB_STRING

engine = db.create_engine(DB_STRING, pool_pre_ping=True)
Session = sessionmaker(bind=engine)


class LibinvBase:
    __table_args__ = {"schema": "libinv"}


Base = declarative_base(cls=LibinvBase)

conn = Session()

metadata = MetaData()
