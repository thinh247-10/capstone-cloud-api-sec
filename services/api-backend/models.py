from sqlalchemy import Column, Integer, String
from database import Base

class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, default="unknown@example.com")
    role = Column(String, default="user")
    
    # Hai cột này chứa rác (Ciphertext) do Vault băm ra, tuyệt đối an toàn nếu bị hack DB
    cccd_ciphertext = Column(String)
    cccd_nonce = Column(String)

class OrderDB(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    item_name = Column(String, index=True)
    price = Column(Integer)
    
    owner_username = Column(String, index=True)