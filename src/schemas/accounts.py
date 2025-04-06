from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, ConfigDict


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str


class RegistrationResponseSchema(UserBaseSchema):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenBaseSchema(BaseModel):
    token: str
    expires_at: datetime


class ActivationTokenSchema(TokenBaseSchema):
    pass


class PasswordResetTokenSchema(TokenBaseSchema):
    pass


class RefreshTokenSchema(TokenBaseSchema):
    pass


class UserProfileBaseSchema(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar: Optional[str] = None
    gender: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    info: Optional[str] = None


class UserProfileCreateSchema(UserProfileBaseSchema):
    pass


class UserProfileResponseSchema(UserProfileBaseSchema):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserResponseSchema(UserBaseSchema):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    profile: Optional[UserProfileResponseSchema] = None

    model_config = ConfigDict(from_attributes=True)
