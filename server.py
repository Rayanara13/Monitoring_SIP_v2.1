from flask import Flask, request, jsonify, send_file, session, redirect, url_for
import json
import time
import subprocess
import threading
import re
import os
import secrets
from pathlib import Path
from functools import wraps
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

PHONES_DIR = Path("users_data")
AUTH_FILE = Path("auth.json")
ENV_FILE = Path(".env")

if not PHONES_DIR.exists():
    PHONES_DIR.mkdir()

users_phones = {} # {username: {number: phone_data}}
lock = threading.Lock()

login_attempts = {}
LOGIN_MAX_ATTEMPTS = 7
LOGIN_BLOCK_SECONDS = 900  # 15 минут

API_AUTH_ROUTES = {"/phones", "/add_phone", "/update_phone", "/delete_phone", "/reorder"}


def load_or_create_auth() -> dict:
    if AUTH_FILE.exists():
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        # Преобразуем старый формат в новый, если нужно
        if isinstance(data, dict) and "username" in data:
            data = {data["username"]: data}
            AUTH_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

    username = "admin"
    password = secrets.token_urlsafe(12)
    event_token = secrets.token_hex(16)

    user_data = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_token": event_token
    }
    
    auth_data = {username: user_data}

    AUTH_FILE.write_text(
        json.dumps(auth_data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("=" * 70)
    print("Создан файл auth.json")
    print(f"Логин: {username}")
    print(f"Пароль: {password}")
    print(f"Токен для /event: {event_token}")
    print("Сохрани эти данные. В auth.json хранится только хэш пароля.")
    print("=" * 70)

    return auth_data


AUTH = load_or_create_auth()


def get_app_secret():
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text().splitlines()
        for line in lines:
            if line.startswith("APP_SECRET_KEY="):
                return line.split("=", 1)[1]
    
    key = secrets.token_hex(32)
    ENV_FILE.write_text(f"APP_SECRET_KEY={key}\n")
    return key


app.secret_key = get_app_secret()
app.permanent_session_lifetime = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # для локального HTTP оставляем False


def is_api_route(path: str) -> bool:
    return path in API_AUTH_ROUTES


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("logged_in") is True:
            return view_func(*args, **kwargs)

        if is_api_route(request.path):
            return jsonify({"ok": False, "error": "Требуется авторизация"}), 401

        return redirect(url_for("login_page"))
    return wrapper


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_login_blocked(ip: str) -> tuple[bool, int]:
    now = time.time()
    record = login_attempts.get(ip)

    if not record:
        return False, 0

    if record["blocked_until"] > now:
        return True, int(record["blocked_until"] - now)

    return False, 0


def register_login_fail(ip: str) -> None:
    now = time.time()
    record = login_attempts.setdefault(ip, {
        "fails": 0,
        "blocked_until": 0
    })

    if record["blocked_until"] > now:
        return

    record["fails"] += 1

    if record["fails"] >= LOGIN_MAX_ATTEMPTS:
        record["blocked_until"] = now + LOGIN_BLOCK_SECONDS
        record["fails"] = 0


def register_login_success(ip: str) -> None:
    if ip in login_attempts:
        del login_attempts[ip]


def load_phones() -> None:
    global users_phones

    # Загружаем телефоны для каждого пользователя из auth.json
    for username in AUTH.keys():
        user_file = PHONES_DIR / f"phones_{username}.json"
        
        # Миграция старого файла для админа
        if username == "admin" and Path("phones.json").exists() and not user_file.exists():
            try:
                Path("phones.json").rename(user_file)
            except Exception:
                pass

        if not user_file.exists():
            user_file.write_text("[]", encoding="utf-8")

        try:
            data = json.loads(user_file.read_text(encoding="utf-8"))
        except Exception:
            data = []

        loaded = {}
        for item in data:
            number = str(item["number"]).strip()
            loaded[number] = {
                "name": item.get("name", number),
                "ip": item.get("ip", ""),
                "state": "В_покое",
                "time": "-",
                "peer": "",
                "duration": "00:00",
                "call_start": None,
                "ping": "?",
                "position": int(item.get("position", 0)),
            }
        users_phones[username] = loaded


def save_phones(username: str) -> None:
    with lock:
        if username not in users_phones:
            return
            
        phones = users_phones[username]
        arr = []
        for number, phone in phones.items():
            arr.append({
                "number": number,
                "name": phone["name"],
                "ip": phone["ip"],
                "position": int(phone.get("position", 0)),
            })

        arr.sort(key=lambda x: x["position"])
        user_file = PHONES_DIR / f"phones_{username}.json"
        user_file.write_text(
            json.dumps(arr, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )


def format_duration(seconds: float) -> str:
    total = int(seconds)
    hours = total // 3600
    minutes = (total % 3600) // 60
    secs = total % 60

    if hours > 0:
        return f"{hours:02}:{minutes:02}:{secs:02}"
    return f"{minutes:02}:{secs:02}"


def normalize_number(value: str | None) -> str:
    if value is None:
        return ""
    return str(value).strip()


def clean_remote(value: str | None) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if value.startswith("$"):
        return ""
    return value


def broadcast_update():
    # SocketIO удален, теперь фронтенд использует поллинг
    pass


def set_state(number: str, state: str, peer: str | None = None) -> None:
    with lock:
        # Ищем номер у всех пользователей
        for username, phones in users_phones.items():
            if number in phones:
                phone = phones[number]
                phone["state"] = state

                if state in ["Разговор", "Исходящий_вызов", "Входящий_вызов", "Удержание", "Снята_трубка"]:
                    phone["time"] = time.strftime("%H:%M:%S")

                if peer is not None and peer != "":
                    phone["peer"] = peer
                else:
                    phone["peer"] = "Не определен"

                if state == "Разговор":
                    if phone["call_start"] is None:
                        phone["call_start"] = time.time()

                if state in {"В_покое", "OFFLINE", "DND"}:
                    phone["call_start"] = None
                    phone["duration"] = "00:00"
                    if state == "В_покое":
                        phone["peer"] = ""

    broadcast_update()


def get_sorted_phones(username: str) -> list[dict]:
    with lock:
        if username not in users_phones:
            return []
            
        phones = users_phones[username]
        now = time.time()
        result = []

        for number, phone in phones.items():
            if phone["call_start"] is not None and phone["state"] == "Разговор":
                phone["duration"] = format_duration(now - phone["call_start"])

            result.append({
                "number": number,
                **phone
            })

    result.sort(key=lambda x: int(x["position"]))
    return result


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if session.get("logged_in") is True:
            return redirect(url_for("panel"))
        return send_file("login.html")

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    ip = get_client_ip()
    blocked, seconds_left = is_login_blocked(ip)
    if blocked:
        return jsonify({
            "ok": False,
            "error": f"Слишком много попыток. Повтори через {seconds_left} сек."
        }), 429

    if username in AUTH and check_password_hash(AUTH[username]["password_hash"], password):
        session.permanent = True
        session["logged_in"] = True
        session["username"] = username
        register_login_success(ip)
        return jsonify({"ok": True})

    register_login_fail(ip)
    return jsonify({"ok": False, "error": "Неверный логин или пароль"}), 401


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({"ok": False, "error": "Введите логин и пароль"}), 400

    if len(username) < 3:
        return jsonify({"ok": False, "error": "Логин слишком короткий"}), 400

    if username in AUTH:
        return jsonify({"ok": False, "error": "Пользователь уже существует"}), 400

    event_token = secrets.token_hex(16)
    AUTH[username] = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_token": event_token
    }

    AUTH_FILE.write_text(json.dumps(AUTH, indent=2, ensure_ascii=False), encoding="utf-8")
    
    # Создаем пустой файл телефонов для нового пользователя
    user_file = PHONES_DIR / f"phones_{username}.json"
    user_file.write_text("[]", encoding="utf-8")
    with lock:
        users_phones[username] = {}

    return jsonify({"ok": True, "event_token": event_token})


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/event")
def event():
    token = request.args.get("token")
    # Проверяем токен у любого пользователя
    target_user = None
    for user_info in AUTH.values():
        if user_info.get("event_token") == token:
            target_user = user_info["username"]
            break

    if not target_user:
        return "Unauthorized", 401

    state = request.args.get("state")
    local = normalize_number(request.args.get("local"))
    remote = clean_remote(request.args.get("remote"))

    user_phone = local

    if not user_phone:
        return "OK"

    # Проверяем, есть ли этот номер у пользователя, чьим токеном воспользовались
    with lock:
        if target_user not in users_phones or user_phone not in users_phones[target_user]:
            # Можно также поискать по всем пользователям, если номер уникален, 
            # но безопаснее ограничивать тем, чей токен.
            # Однако в SIP один номер может быть только у одного человека в системе.
            # Если мы хотим, чтобы /event работал глобально для всех номеров, 
            # мы можем использовать специальный админский токен или проверять всех.
            pass

    if state == "Setup":
        set_state(user_phone, "Исходящий_вызов", remote)

    elif state == "Ringing":
        set_state(user_phone, "Входящий_вызов", remote)

    elif state == "Connected":
        current_peer = remote
        if not current_peer:
            with lock:
                # Ищем по всем, так как set_state тоже ищет по всем
                for u in users_phones.values():
                    if user_phone in u:
                        current_peer = u[user_phone]["peer"]
                        break
        set_state(user_phone, "Разговор", current_peer)

    elif state == "Idle":
        set_state(user_phone, "В_покое")

    elif state == "Hold":
        set_state(user_phone, "Удержание", remote)

    elif state == "DND":
        set_state(user_phone, "DND")

    elif state == "OffHook":
        set_state(user_phone, "Снята_трубка")

    elif state == "OnHook":
        set_state(user_phone, "В_покое")

    print(
        f"{time.strftime('%H:%M:%S')} | user={target_user} | state={state} | local={local} | remote={remote}"
    )
    return "OK"


@app.route("/phones")
@login_required
def get_phones():
    username = session.get("username")
    return jsonify(get_sorted_phones(username))


@app.route("/add_phone", methods=["POST"])
@login_required
def add_phone():
    username = session.get("username")
    data = request.get_json(force=True)

    number = normalize_number(data.get("number"))
    name = normalize_number(data.get("name"))
    ip = normalize_number(data.get("ip"))

    if not number:
        return jsonify({"ok": False, "error": "Не указан номер"}), 400

    with lock:
        if username not in users_phones:
            users_phones[username] = {}
            
        if number in users_phones[username]:
            return jsonify({"ok": False, "error": "Такой номер уже существует"}), 400

        next_position = len(users_phones[username])
        users_phones[username][number] = {
            "name": name or number,
            "ip": ip,
            "state": "В_покое",
            "time": "-",
            "peer": "",
            "duration": "00:00",
            "call_start": None,
            "ping": "?",
            "position": next_position,
        }

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/update_phone", methods=["POST"])
@login_required
def update_phone():
    username = session.get("username")
    data = request.get_json(force=True)

    number = normalize_number(data.get("number"))
    name = normalize_number(data.get("name"))
    ip = normalize_number(data.get("ip"))

    with lock:
        if username not in users_phones or number not in users_phones[username]:
            return jsonify({"ok": False, "error": "Номер не найден"}), 404

        users_phones[username][number]["name"] = name or number
        users_phones[username][number]["ip"] = ip

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/delete_phone", methods=["POST"])
@login_required
def delete_phone():
    username = session.get("username")
    data = request.get_json(force=True)
    number = normalize_number(data.get("number"))

    with lock:
        if username in users_phones and number in users_phones[username]:
            del users_phones[username][number]

            ordered_numbers = sorted(
                users_phones[username].keys(),
                key=lambda n: int(users_phones[username][n]["position"])
            )
            for idx, num in enumerate(ordered_numbers):
                users_phones[username][num]["position"] = idx

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/reorder", methods=["POST"])
@login_required
def reorder():
    username = session.get("username")
    order = request.get_json(force=True)

    if not isinstance(order, list):
        return jsonify({"ok": False, "error": "Неверный формат"}), 400

    with lock:
        if username not in users_phones:
            return jsonify({"ok": False, "error": "Пользователь не найден"}), 404
            
        for idx, number in enumerate(order):
            number = str(number)
            if number in users_phones[username]:
                users_phones[username][number]["position"] = idx

    save_phones(username)
    broadcast_update()
    return jsonify({"ok": True})


@app.route("/")
@login_required
def panel():
    return send_file("panel.html")


@app.route("/favicon.ico")
def favicon():
    return "OK", 200, {"Content-Type": "image/x-icon"}


@app.route("/user_info")
@login_required
def user_info():
    username = session.get("username")
    return jsonify({
        "username": username,
        "event_token": AUTH[username].get("event_token"),
        "is_admin": username == "admin"
    })


@app.route("/admin/users")
@login_required
def admin_users():
    username = session.get("username")
    if username != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403
    
    users = []
    for uname, info in AUTH.items():
        users.append({
            "username": info.get("username"),
            "created_at": info.get("created_at"),
            "event_token": info.get("event_token")
        })
    return jsonify({"ok": True, "users": users})


def ping_once(ip: str):
    if not ip:
        return None

    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            return None

        match = re.search(r"time[=<]\s*(\d+)", result.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1))

        match = re.search(r"время[=<]\s*(\d+)", result.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1))

        return 1
    except Exception:
        return None


def ping_loop() -> None:
    executor = ThreadPoolExecutor(max_workers=20)
    while True:
        snapshot = []
        with lock:
            for username, phones in users_phones.items():
                for number, phone in phones.items():
                    snapshot.append((username, number, phone["ip"]))

        def task(uname, num, ip_addr):
            latency = ping_once(ip_addr)
            changed = False
            with lock:
                if uname not in users_phones or num not in users_phones[uname]:
                    return False
                
                phone = users_phones[uname][num]
                old_ping = phone.get("ping")
                old_state = phone.get("state")

                if latency is None:
                    phone["ping"] = "Недоступен"
                    phone["state"] = "OFFLINE"
                    phone["call_start"] = None
                    phone["duration"] = "00:00"
                else:
                    phone["ping"] = f"{latency} ms"
                    if phone["state"] == "OFFLINE":
                        phone["state"] = "В_покое"
                
                if phone["ping"] != old_ping or phone["state"] != old_state:
                    changed = True
            return changed

        results = list(executor.map(lambda p: task(*p), snapshot))
        
        if any(results):
            broadcast_update()

        time.sleep(60)




if __name__ == "__main__":
    load_phones()
    threading.Thread(target=ping_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8000)