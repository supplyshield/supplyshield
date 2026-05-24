import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from libinv.base import engine
from libinv.models import Repository

logger = logging.getLogger(__name__)


def fetch_repository(repository_id):
    try:
        Session = sessionmaker(bind=engine)
        conn = Session()
        result = conn.query(Repository).filter_by(id=repository_id).first()
        return result
    except SQLAlchemyError as e:
        conn.rollback()
        logger.error("Failed to fetch repository %s: %s", repository_id, e)
    finally:
        conn.close()
