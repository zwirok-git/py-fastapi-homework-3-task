from datetime import datetime, timezone
from typing import Annotated, cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def token_is_expired(expires_at: datetime) -> bool:
    expires_at = cast(datetime, expires_at)

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return expires_at <= datetime.now(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> UserRegistrationResponseSchema:
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_stmt)
    user_group = group_result.scalars().first()

    try:
        user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=user.id, email=user.email)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token = user.activation_token
    if (
            not token
            or token.token != activation_data.token
            or token_is_expired(token.expires_at)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    message = ("If you are registered, "
               "you will receive an email with instructions.")

    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.user_id == user.id)
            )
            db.add(PasswordResetTokenModel(user_id=user.id))
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()

    return MessageResponseSchema(message=message)


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    token = user.password_reset_token
    if (
            not token
            or token.token != reset_data.token
            or token_is_expired(token.expires_at)
    ):
        if token:
            try:
                await db.delete(token)
                await db.commit()
            except SQLAlchemyError:
                await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = reset_data.password
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)
        ],
        settings: Annotated[
            BaseAppSettings, Depends(get_settings)
        ],
) -> UserLoginResponseSchema:
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)
        ],
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    stmt = (select(RefreshTokenModel)
            .where(RefreshTokenModel.token == token_data.refresh_token))
    result = await db.execute(stmt)
    refresh_token = result.scalars().first()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = payload.get("user_id")
    if refresh_token.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = await db.get(UserModel, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
