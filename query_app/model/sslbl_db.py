from sqlalchemy import Column, String, Integer, create_engine, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from query_app.config import DATA_PATH

engine = create_engine('sqlite:////' + DATA_PATH + '/sslbl.db')
Session = sessionmaker(bind=engine)

Base = declarative_base()


class Certificate(Base):

    __tablename__ = 'certificate'

    id = Column(Integer, primary_key=True)
    utc_time = Column(String(20))
    sha1 = Column(String(40))
    subject_common_name = Column(String(100))
    subject = Column(String(100))
    issuer_common_name = Column(String(100))
    issuer = Column(String(100))
    ssl_ver = Column(String(10))
    reason = Column(String(20))
    ips = relationship('IP', backref='sha1')


class IP(Base):

    __tablename__ = 'ip'

    id = Column(Integer, primary_key=True)
    utc_time = Column(String(20))
    md5 = Column(String(32))
    dst_ip = Column(String(15))
    dst_port = Column(Integer)
    certificate_sha1 = Column(String(40), ForeignKey('certificate.sha1'))


# Base.metadata.create_all(engine)
