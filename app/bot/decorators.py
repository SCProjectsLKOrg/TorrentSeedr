"""Custom decorators for handlers."""

import functools
import inspect
from collections.abc import Callable, Coroutine
from typing import Any

from seedrcc import AsyncSeedr, Token
from seedrcc.exceptions import APIError, AuthenticationError, SeedrError
from structlog import get_logger
from telethon import errors, events

from app.bot.views import ViewResponse
from app.bot.views.accounts_view import render_no_account
from app.database import get_session
from app.database.models import User
from app.database.repository import AccountRepository, UserRepository
from app.exceptions import NoAccountError
from app.services.seedr import on_token_refresh
from app.utils.language import Translator, get_language_service

logger = get_logger(__name__)
language_service = get_language_service()


async def _inject_dependencies(
    func: Callable[..., Coroutine],
    event: events.NewMessage.Event | events.CallbackQuery.Event,
    user: User,
    translator: Translator,
    require_auth: bool,
) -> dict:
    """Injects dependencies, including the Seedr client if required."""
    dependencies = {
        "event": event,
        "user": user,
        "translator": translator,
        "client": event.client,
    }

    if require_auth:
        if not user.default_account_id:
            raise NoAccountError()

        async with get_session() as session:
            account = await AccountRepository(session).get_by_id(user.default_account_id, user.id)

        if not account:
            raise NoAccountError()

        token_instance = Token.from_base64(account.token)
        callback = functools.partial(on_token_refresh, account_id=account.id, user_id=user.id)
        seedr_client = AsyncSeedr(token=token_instance, on_token_refresh=callback)
        dependencies["seedr_client"] = seedr_client

    handler_signature = inspect.signature(func)
    return {key: value for key, value in dependencies.items() if key in handler_signature.parameters}


async def _handle_exception(
    event: events.NewMessage.Event | events.CallbackQuery.Event,
    translator: Translator,
    exception: Exception,
):
    """Handle exceptions, log them, and send an appropriate response to the user."""
    if isinstance(exception, events.StopPropagation):
        raise exception

    view = None

    if isinstance(exception, NoAccountError):
        view = render_no_account(translator)

    elif isinstance(exception, AuthenticationError):
        error_text = str(exception) or translator.get("tokenExpired")
        view = ViewResponse(message=error_text)

    elif isinstance(exception, (APIError)):
        error_text = translator.get("somethingWrong")
        view = ViewResponse(message=error_text)
        logger.error(f"APIError/SeedrError: {exception}", raw_response=exception.response, exc_info=True)

    elif isinstance(exception, (SeedrError)):
        error_text = translator.get("somethingWrong")
        view = ViewResponse(message=error_text)
        logger.error(f"APIError/SeedrError: {exception}", exc_info=True)

    elif isinstance(exception, errors.AlreadyInConversationError):
        pass

    # Any other unhandled exceptions
    else:
        error_text = translator.get("somethingWrong")
        view = ViewResponse(message=error_text)
        logger.error(f"Unhandled exception: {exception}", exc_info=True)

    if view:
        if isinstance(event, events.CallbackQuery.Event):
            await event.edit(view.message, buttons=view.buttons)
        else:
            await event.respond(view.message, buttons=view.buttons)

    raise events.StopPropagation()


def setup_handler(require_auth: bool = False):
    """
    Primary decorator for handlers. It provides dependency injection and centralized exception handling.
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(event: events.NewMessage.Event | events.CallbackQuery.Event, *args: Any, **kwargs: Any):
            translator = None
            try:
                user = kwargs.get("user")
                if not user:
                    username = event.sender.username if event.sender else None
                    async with get_session() as session:
                        user = await UserRepository(session).get_or_create(
                            telegram_id=event.sender_id, username=username
                        )

                translator = language_service.get_translator(user.language)

                injected_kwargs = await _inject_dependencies(func, event, user, translator, require_auth)

                # Merge original kwargs with injected dependencies (injected takes precedence)
                final_kwargs = {**kwargs, **injected_kwargs}

                return await func(*args, **final_kwargs)
            except Exception as err:
                translator = language_service.get_translator() if translator is None else translator
                await _handle_exception(event, translator, err)

        return wrapper

    return decorator
