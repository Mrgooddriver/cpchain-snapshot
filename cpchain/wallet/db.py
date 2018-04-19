import os.path as osp

# https://qiita.com/zakuro9715/items/7e393ef1c80da8811027
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker

from cpchain import root_dir, config

dbpath = osp.join(root_dir, config.wallet.dbpath)
engine = create_engine('sqlite:///{dbpath}'.format(dbpath=dbpath), echo=True)

Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


class FileInfo(Base):
    __tablename__ = 'fileinfo'
    id = Column(Integer, primary_key=True)
    hashcode = Column(String)
    name = Column(String)
    path = Column(String)
    size = Column(Integer)
    remote_type = Column(String)
    remote_uri = Column(String)
    is_published = Column(Boolean)
    aes_key = Column(String)
    market_hash = Column(String)

    def __repr__(self):
        return "<FileInfo(path='%s', remote_uri='%s')>" % (self.path, self.remote_uri)


class BuyerFileInfo(Base):
    __tablename__ = 'buyerfileinfo'
    id = Column(Integer, primary_key=True)
    order_id = Column(Integer)
    market_hash = Column(String)
    file_uuid = Column(String)
    file_title = Column(String)
    path = Column(String)
    size = Column(Integer)
    is_downloaded = Column(Boolean)

    def __repr__(self):
        return "<BuyerFileInfo(path='%s', remote_uri='%s')>" % (self.path, self.remote_uri)


def create_table():
    """Use this to create all tables.
    """
    Base.metadata.create_all(engine)


if not osp.isfile(dbpath):
    create_table()
