from __future__ import annotations

import asyncio
import sys
import threading
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from .settings import settings
from .licenses import activate_license, check_access
from .commands import enqueue_command

application: Application | None = None
_loop: asyncio.AbstractEventLoop | None = None


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if context.args:
        try:
            await activate_license(context.args[0], update.effective_chat.id)
            await update.message.reply_text("Лицензия активирована! Теперь вы будете получать уведомления об атаках.")
        except Exception as e:
            await update.message.reply_text(f"Ошибка активации: {e}")
    else:
        await update.message.reply_text(
            "WAF Control Bot\n\n"
            "Для активации: /start <license_key>\n"
            "или: /activate <license_key>"
        )


async def cmd_activate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Использование: /activate <license_key>")
        return
    try:
        await activate_license(context.args[0], update.effective_chat.id)
        await update.message.reply_text("Лицензия активирована!")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        await check_access(update.effective_chat.id)
        await update.message.reply_text("Статус: активен")
    except:
        await update.message.reply_text("Статус: не активирован")


async def cmd_unblock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Разблокировка IP адреса"""
    if not context.args:
        await update.message.reply_text("Использование: /unblock <IP>")
        return
    try:
        license_hash = await check_access(update.effective_chat.id)
    except:
        await update.message.reply_text("Чат не активирован")
        return
    
    ip = context.args[0]
    await enqueue_command(license_hash, "unblock_ip", {"ip": ip})
    await update.message.reply_text(f"IP {ip} разблокирован")


async def cmd_block(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Блокировка IP адреса"""
    if not context.args:
        await update.message.reply_text("Использование: /block <IP> [TTL_секунды]")
        return
    try:
        license_hash = await check_access(update.effective_chat.id)
    except:
        await update.message.reply_text("Чат не активирован")
        return
    
    ip = context.args[0]
    ttl = int(context.args[1]) if len(context.args) > 1 else 3600
    await enqueue_command(license_hash, "block_ip", {"ip": ip, "ttl": ttl})
    await update.message.reply_text(f"IP {ip} заблокирован на {ttl} секунд")


async def cmd_addrule(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Добавление правила regex"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "Использование: /addrule <категория> <pattern>\n"
            "Категории: SQLI, XSS, CMD, TRAVERSAL, SSRF\n"
            "Пример: /addrule SQLI malicious_pattern"
        )
        return
    
    chat_id = update.effective_chat.id
    
    try:
        license_hash = await check_access(chat_id)
    except:
        await update.message.reply_text("❌ Чат не активирован")
        return
    
    category = context.args[0].upper()
    pattern = " ".join(context.args[1:])
    
    if category not in {"SQLI", "XSS", "CMD", "TRAVERSAL", "SSRF"}:
        await update.message.reply_text("❌ Неизвестная категория")
        return
    
    await enqueue_command(license_hash, "add_rule", {
        "category": category,
        "pattern": pattern,
        "target": "query",
        "weight": 5
    })
    await update.message.reply_text(f"✅ Правило добавлено: {category} -> {pattern}")


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Справка по командам"""
    help_text = """
🛡 *WAF Control Bot*

*Управление блокировками:*
/block <IP> [TTL] - заблокировать IP
/unblock <IP> - разблокировать IP

*Управление правилами:*
/addrule <категория> <pattern> - добавить правило

*Информация:*
/status - статус активации
/help - эта справка

*Активация:*
/activate <license\\_key> - активировать лицензию
    """
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    
    data = query.data
    chat_id = query.message.chat_id
    
    try:
        license_hash = await check_access(chat_id)
    except:
        await query.edit_message_text("❌ Чат не активирован")
        return
    
    parts = data.split(":")
    action = parts[0]
    ip = parts[1] if len(parts) > 1 else ""
    
    if action == "block1h":
        await enqueue_command(license_hash, "block_ip", {"ip": ip, "ttl": 3600})
        await query.edit_message_text(f"✅ IP {ip} заблокирован на 1 час")
    elif action == "blockperm":
        await enqueue_command(license_hash, "block_ip", {"ip": ip, "ttl": 86400 * 365})
        await query.edit_message_text(f"✅ IP {ip} заблокирован навсегда")
    elif action == "unblock":
        await enqueue_command(license_hash, "unblock_ip", {"ip": ip})
        await query.edit_message_text(f"✅ IP {ip} разблокирован")
    elif action == "ratelimit":
        # Применяем мягкую блокировку через rate limit
        await enqueue_command(license_hash, "block_ip", {"ip": ip, "ttl": 300})
        await query.edit_message_text(f"⚠️ IP {ip} ограничен на 5 минут")
    else:
        await query.edit_message_text("❌ Неизвестное действие")


async def _send_impl(chat_id: int, text: str, event: dict[str, Any]) -> None:
    if application is None:
        print("[bot] application is None", file=sys.stderr)
        return
    
    ip = event.get("client_ip", "")
    
    buttons = [
        [
            InlineKeyboardButton("⏱ Блок 1 час", callback_data=f"block1h:{ip}"),
            InlineKeyboardButton("🚫 Блок навсегда", callback_data=f"blockperm:{ip}"),
        ],
        [
            InlineKeyboardButton("⚠️ Rate limit 5м", callback_data=f"ratelimit:{ip}"),
            InlineKeyboardButton("✅ Разблокировать", callback_data=f"unblock:{ip}"),
        ]
    ]
    
    try:
        await application.bot.send_message(
            chat_id=chat_id,
            text=text,
            reply_markup=InlineKeyboardMarkup(buttons),
        )
        print(f"[bot] sent message to {chat_id}", file=sys.stderr)
    except Exception as e:
        print(f"[bot] send error: {e}", file=sys.stderr)


async def send_message(chat_id: int, text: str, event: dict[str, Any]) -> None:
    print(f"[bot] send_message called for chat_id={chat_id}", file=sys.stderr)
    
    if _loop is None:
        print("[bot] _loop is None, calling directly", file=sys.stderr)
        await _send_impl(chat_id, text, event)
        return
    
    fut = asyncio.run_coroutine_threadsafe(_send_impl(chat_id, text, event), _loop)
    try:
        fut.result(timeout=10.0)
    except Exception as e:
        print(f"[bot] future error: {e}", file=sys.stderr)


def _run_polling() -> None:
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    
    if application is None:
        return
    
    print("[bot] starting polling...", file=sys.stderr)
    
    try:
        _loop.run_until_complete(application.initialize())
        _loop.run_until_complete(application.start())
        _loop.run_until_complete(application.updater.start_polling(drop_pending_updates=True))
        print("[bot] polling started", file=sys.stderr)
        _loop.run_forever()
    except Exception as e:
        print(f"[bot] polling error: {e}", file=sys.stderr)


def start_bot() -> None:
    global application
    
    if not settings.bot_token:
        print("[bot] no bot_token, skipping", file=sys.stderr)
        return
    
    if application is not None:
        print("[bot] already started", file=sys.stderr)
        return
    
    print(f"[bot] starting with token {settings.bot_token[:10]}...", file=sys.stderr)
    
    application = ApplicationBuilder().token(settings.bot_token).build()
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("activate", cmd_activate))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("block", cmd_block))
    application.add_handler(CommandHandler("unblock", cmd_unblock))
    application.add_handler(CommandHandler("addrule", cmd_addrule))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CallbackQueryHandler(handle_callback))
    
    threading.Thread(target=_run_polling, daemon=True).start()
