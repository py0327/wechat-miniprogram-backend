
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import cloudinary
import cloudinary.uploader
import re
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 初始化应用
app = FastAPI(title="微信小程序后端服务", description="用户认证与管理")

# 数据库配置
MONGO_URL = os.environ.get("MONGODB_URL", "mongodb://localhost:27017/")
client = AsyncIOMotorClient(MONGO_URL)
db = client["wechat_miniprogram"]
users_collection = db["users"]

# Cloudinary配置
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

# JWT配置
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1天

# 密码哈希
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 数据模型
class UserBase(BaseModel):
    username: str
    nickName: str
    isMale: int
    avatar: Optional[str] = None
    description: Optional[str] = None

class UserCreate(UserBase):
    password: constr(min_length=6, max_length=16)  # 密码长度6-16位

class User(UserBase):
    id: str
    created_at: datetime

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class TokenData(BaseModel):
    username: Optional[str] = None

# 工具函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(username: str):
    user = await users_collection.find_one({"username": username})
    if user:
        return User(**user)
    return None

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(OAuth2PasswordRequestForm)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无法验证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token.access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# 路由 - 头像上传
@app.post("/upload/avatar", summary="上传用户头像")
async def upload_avatar(file: UploadFile = File(...)):
    try:
        # 上传到Cloudinary
        result = cloudinary.uploader.upload(
            file.file,
            folder="wechat_avatars",
            transformation=[
                {"width": 200, "height": 200, "crop": "fill"},
                {"quality": "auto:good"}
            ]
        )
        return {"code": 200, "path": result["secure_url"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"上传失败: {str(e)}")

# 路由 - 用户注册
@app.post("/register", summary="用户注册", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    # 检查手机号格式
    if not re.match(r'^1[3-9]\d{9}$', user.username):
        raise HTTPException(status_code=400, detail="手机号格式错误")
    
    # 检查用户名是否存在
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 哈希密码
    hashed_password = get_password_hash(user.password)
    
    # 准备用户数据
    user_data = user.dict()
    user_data["password"] = hashed_password
    user_data["created_at"] = datetime.now()
    
    # 插入数据库
    result = await users_collection.insert_one(user_data)
    
    # 返回创建的用户
    created_user = await users_collection.find_one({"_id": result.inserted_id})
    created_user["id"] = str(created_user["_id"])
    del created_user["_id"]
    del created_user["password"]
    
    return {"code": 201, "message": "注册成功", "user": created_user}

# 路由 - 用户登录
@app.post("/login", summary="用户登录")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # 准备返回的用户数据
    user_data = user.dict()
    del user_data["password"]
    
    return {"code": 200, "message": "登录成功", "token": access_token, "user": user_data}

# 路由 - 获取当前用户信息
@app.get("/users/me", summary="获取当前用户信息")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user    