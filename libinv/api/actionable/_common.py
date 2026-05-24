from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from libinv.base import engine
from libinv.models import Repository


def fetch_repository(repository_id):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        result = conn.query(Repository).filter_by(id=repository_id).first()
        return result
    except SQLAlchemyError as e:
        conn.rollback()
        print(str(e))
    finally:
        conn.close()
