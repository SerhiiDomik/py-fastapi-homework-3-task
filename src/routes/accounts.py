from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import get_db
from database.models.accounts import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserModel,
    UserGroupEnum,
)
from database.validators.accounts import (
    validate_email,
    validate_password_strength,
)
from exceptions.security import InvalidTokenError, TokenExpiredError
from schemas.accounts import (
    LoginResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    RefreshTokenRequestSchema,
    RegistrationResponseSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserRegistrationRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=RegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    try:
        validate_email(user_data.email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    try:
        validate_password_strength(user_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    existing_user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        user = UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            is_active=False,
            group_id=UserGroupEnum.USER.value,
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()

        return RegistrationResponseSchema.model_validate(user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == activation_data.email,
            ActivationTokenModel.token == activation_data.token,
        )
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if token_record.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    token_record.user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    request_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    result = await db.execute(
        select(UserModel).where(
            UserModel.email == request_data.email, UserModel.is_active == True
        )
    )
    user = result.scalar_one_or_none()

    if user:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.flush()

        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        validate_password_strength(reset_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    try:
        result = await db.execute(
            select(PasswordResetTokenModel)
            .options(joinedload(PasswordResetTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == reset_data.email,
                PasswordResetTokenModel.token == reset_data.token,
            )
        )
        token_record = result.scalar_one_or_none()

        if not token_record:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user.has(email=reset_data.email)
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        expires_at = cast(datetime, token_record.expires_at).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token_record.user._hashed_password = hash_password(reset_data.password)
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/", response_model=LoginResponseSchema, status_code=status.HTTP_201_CREATED
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        validate_email(login_data.email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )

    result = await db.execute(
        select(UserModel).where(UserModel.email == login_data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return LoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
        token_type="bearer",
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    refresh_data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = payload.get("user_id")
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    result = await db.execute(
        select(RefreshTokenModel).filter_by(token=refresh_data.refresh_token)
    )
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    result = await db.execute(select(UserModel).filter_by(id=user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=access_token)
