"""Handler for adding torrents via magnet links or torrent files."""

import seedrcc.exceptions
from seedrcc import AsyncSeedr
from telethon import events

from app.bot.decorators import setup_handler
from app.bot.views.add_torrent_view import (
    render_add_torrent_success,
    render_file_too_large_message,
    render_invalid_magnet_message,
    render_item_already_in_queue,
    render_not_enough_space_added_to_wishlist,
    render_queue_full_added_to_wishlist,
)
from app.bot.views.shared_view import render_processing_message
from app.config import settings
from app.database.models import User
from app.utils import extract_magnet_from_text, format_size
from app.utils.language import Translator


@setup_handler(require_auth=True)
async def add_torrent_handler(
    event: events.NewMessage.Event,
    user: User,
    translator: Translator,
    seedr_client: AsyncSeedr,
    magnet_link: str | None = None,
    **kwargs,
):
    """Handle adding torrent from magnet link."""
    if not magnet_link:
        magnet_link = extract_magnet_from_text(event.message.text)

    view = render_processing_message(translator)
    status_message = await event.respond(view.message, buttons=view.buttons)

    try:
        result = await seedr_client.add_torrent(magnet_link)

        if result.user_torrent_id:
            view = render_add_torrent_success(translator, result.title)
            await status_message.edit(view.message, buttons=view.buttons)
        else:
            view = render_item_already_in_queue(translator)
            await status_message.edit(view.message, buttons=view.buttons)
    except seedrcc.exceptions.APIError as err:
        if err.error_type in ("queue_full_added_to_wishlist", "queue_full_wishlist_full"):
            view = render_queue_full_added_to_wishlist(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        elif err.error_type in ("not_enough_space_added_to_wishlist", "not_enough_space_wishlist_full"):
            view = render_not_enough_space_added_to_wishlist(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        elif err.error_type == "parsing_error":
            view = render_invalid_magnet_message(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        else:
            raise


@setup_handler(require_auth=True)
async def handle_torrent_file(
    event: events.NewMessage.Event,
    user: User,
    translator: Translator,
    seedr_client: AsyncSeedr,
):
    """Handle torrent file upload."""
    # Check file size before downloading
    if event.message.file.size > settings.max_torrent_file_size:
        max_size_mb = format_size(settings.max_torrent_file_size)
        view = render_file_too_large_message(max_size_mb, translator)
        await event.respond(view.message, buttons=view.buttons)
        return

    view = render_processing_message(translator)
    status_message = await event.respond(view.message, buttons=view.buttons)

    file_bytes = await event.message.download_media(bytes)

    try:
        result = await seedr_client.add_torrent(file_bytes)

        if result.user_torrent_id:
            view = render_add_torrent_success(translator, result.title)
            await status_message.edit(view.message, buttons=view.buttons)
        else:
            view = render_item_already_in_queue(translator)
            await status_message.edit(view.message, buttons=view.buttons)
    except seedrcc.exceptions.APIError as err:
        if err.error_type == "queue_full_added_to_wishlist":
            view = render_queue_full_added_to_wishlist(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        elif err.error_type == "not_enough_space_added_to_wishlist":
            view = render_not_enough_space_added_to_wishlist(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        elif err.error_type == "parsing_error":
            view = render_invalid_magnet_message(translator)
            await status_message.edit(view.message, buttons=view.buttons)
        else:
            raise
