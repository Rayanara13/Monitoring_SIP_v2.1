from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_socketio import SocketIO
import json
import time
import subprocess
import threading
import re
import secrets
import socket
import urllib.request
import urllib.parse
from pathlib import Path
from functools import wraps
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# allow_upgrades=True — используем WebSocket если доступен, иначе polling
# ping_timeout/ping_interval — агрессивное обнаружение потери соединения
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    ping_timeout=10,
    ping_interval=5,
)

PHONES_DIR = Path("users_data")
AUTH_FILE = Path("auth.json")
ENV_FILE = Path(".env")
BLOCKS_FILE = Path("users_data/login_blocks.json")

if not PHONES_DIR.exists():
    PHONES_DIR.mkdir()

users_phones = {} # {username: {number: phone_data}}
lock = threading.Lock()

LOGIN_MAX_ATTEMPTS = 7
LOGIN_BLOCK_SECONDS = 900  # 15 минут


def load_login_attempts() -> dict:
    if BLOCKS_FILE.exists():
        try:
            data = json.loads(BLOCKS_FILE.read_text(encoding="utf-8"))
            now = time.time()
            # Удаляем просроченные блокировки при загрузке
            return {ip: rec for ip, rec in data.items() if rec.get("blocked_until", 0) > now}
        except Exception:
            pass
    return {}


def save_login_attempts() -> None:
    try:
        BLOCKS_FILE.write_text(
            json.dumps(login_attempts, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception:
        pass


login_attempts = load_login_attempts()

# Rate-limit для /event: не более 120 событий в минуту с одного IP
event_rate: dict = {}  # {ip: {"count": int, "window_start": float}}
EVENT_RATE_LIMIT = 120
EVENT_RATE_WINDOW = 60


def is_event_rate_limited(ip: str) -> bool:
    now = time.time()
    rec = event_rate.setdefault(ip, {"count": 0, "window_start": now})
    if now - rec["window_start"] >= EVENT_RATE_WINDOW:
        rec["count"] = 0
        rec["window_start"] = now
    rec["count"] += 1
    return rec["count"] > EVENT_RATE_LIMIT

API_AUTH_ROUTES = {"/phones", "/add_phone", "/update_phone", "/delete_phone", "/reorder"}


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # не обязательно, чтобы хост существовал
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


def get_env_value(key: str, default: str = "") -> str:
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return default


TARGET_IP = get_env_value("TARGET_IP", "10.58.22.25")
TARGET_PORT = int(get_env_value("TARGET_PORT", "8000"))


def duplicate_get_request(url_path, query_params):
    if LOCAL_IP == TARGET_IP:
        return

    # Строим URL для дублирования
    target_url = f"http://{TARGET_IP}:{TARGET_PORT}{url_path}"
    if query_params:
        target_url += "?" + urllib.parse.urlencode(query_params)
    
    def send_request():
        try:
            with urllib.request.urlopen(target_url, timeout=5) as response:
                response.read()
        except Exception as e:
            # Игнорируем ошибки при дублировании, чтобы не мешать основной работе
            pass

    threading.Thread(target=send_request, daemon=True).start()


@app.before_request
def before_request_func():
    if request.method == "GET" and LOCAL_IP != TARGET_IP:
        # Не дублируем статические файлы и иконки, если нужно сэкономить ресурсы
        # Но по ТЗ "отправлял дублирубщие get запросы", так что дублируем всё
        duplicate_get_request(request.path, request.args.to_dict())


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
    with open(ENV_FILE, "a") as f:
        f.write(f"APP_SECRET_KEY={key}\n")
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
        save_login_attempts()


def register_login_success(ip: str) -> None:
    if ip in login_attempts:
        del login_attempts[ip]
        save_login_attempts()


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
    
    # Регулярное выражение: ищем sip: (без учета регистра), захватываем все до @ или :
    match = re.search(r'(?i)sip:([^@:]+)', value)
    if match:
        return match.group(1)
    
    # Если есть @, берем все до него
    if '@' in value:
        return value.split('@')[0]
    
    # Если нет sip: и нет @, но есть :, может это номер:порт?
    if ':' in value and not value.startswith(':'):
         return value.split(':')[0]

    return value


def broadcast_update():
    # Вызывается как из request-треда, так и из фонового ping_loop.
    # start_background_task гарантирует выполнение в eventlet green-thread контексте,
    # что надёжнее прямого emit из обычного threading.Thread.
    def _emit():
        socketio.emit('phones_update', {'data': 'updated'}, namespace='/')
    socketio.start_background_task(_emit)


def set_state(number: str, state: str, peer: str | None = None) -> None:
    with lock:
        # Ищем номер у всех пользователей
        for username, phones in users_phones.items():
            if number in phones:
                phone = phones[number]
                phone["state"] = state

                if state in ["Разговор", "Исходящий_вызов", "Входящий_вызов", "Удержание", "Снята_трубка"]:
                    phone["time"] = time.strftime("%H:%M:%S")
                    if phone["call_start"] is None:
                        phone["call_start"] = time.time()

                # Миграция номера собеседника: если в новом событии peer не указан,
                # но он был определен ранее в рамках этого же вызова, сохраняем старый.
                if peer is not None and peer != "":
                    phone["peer"] = peer
                elif state in ["Разговор", "Удержание"] and phone.get("peer") and phone["peer"] != "Не определен":
                    # Сохраняем существующий peer для этих состояний, если новый не пришел
                    pass
                elif state in ["Разговор", "Исходящий_вызов", "Входящий_вызов", "Удержание", "Снята_трубка"]:
                    # Если peer вообще не был задан ранее
                    if not phone.get("peer"):
                        phone["peer"] = "Не определен"
                else:
                    phone["peer"] = ""

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
        result = []

        for number, phone in phones.items():
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
@login_required
def register():
    # Регистрация доступна только админу
    if session.get("username") != "admin":
        return jsonify({"ok": False, "error": "Доступ запрещен"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()

    if not username:
        return jsonify({"ok": False, "error": "Введите логин"}), 400

    if len(username) < 3:
        return jsonify({"ok": False, "error": "Логин слишком короткий"}), 400

    if username in AUTH:
        return jsonify({"ok": False, "error": "Пользователь уже существует"}), 400

    # Генерируем пароль автоматически
    password = secrets.token_urlsafe(10)
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
    if not user_file.exists():
        user_file.write_text("[]", encoding="utf-8")
    
    with lock:
        users_phones[username] = {}

    return jsonify({
        "ok": True, 
        "password": password, 
        "event_token": event_token
    })


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/event")
def event():
    if is_event_rate_limited(get_client_ip()):
        return "Too Many Requests", 429

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
        # Если remote пустой — сохраняем peer из предыдущего состояния (Ringing/Setup)
        if not remote:
            with lock:
                for u in users_phones.values():
                    if user_phone in u:
                        remote = u[user_phone].get("peer") or ""
                        break
        set_state(user_phone, "Разговор", remote)

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


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_file(Path("static") / filename)


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


# ── Общая библиотека карточек ─────────────────────────────────────────────────

def get_user_meta(username: str) -> dict:
    meta_file = PHONES_DIR / f"meta_{username}.json"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"shared": False}


def save_user_meta(username: str, meta: dict) -> None:
    meta_file = PHONES_DIR / f"meta_{username}.json"
    meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


@app.route("/my_shared_status")
@login_required
def my_shared_status():
    username = session.get("username")
    meta = get_user_meta(username)
    return jsonify({"ok": True, "shared": meta.get("shared", False)})


@app.route("/shared_sets")
@login_required
def shared_sets():
    result = []
    for uname in AUTH.keys():
        meta = get_user_meta(uname)
        if not meta.get("shared"):
            continue
        with lock:
            phones = users_phones.get(uname, {})
            cards = [
                {"number": num, "name": p["name"], "ip": p["ip"]}
                for num, p in phones.items()
            ]
        result.append({
            "username": uname,
            "count": len(cards),
            "phones": cards,
        })
    return jsonify({"ok": True, "sets": result})


@app.route("/toggle_shared", methods=["POST"])
@login_required
def toggle_shared():
    username = session.get("username")
    meta = get_user_meta(username)
    meta["shared"] = not meta.get("shared", False)
    save_user_meta(username, meta)
    return jsonify({"ok": True, "shared": meta["shared"]})


@app.route("/import_set", methods=["POST"])
@login_required
def import_set():
    current_user = session.get("username")
    data = request.get_json(silent=True) or {}
    source = str(data.get("username", "")).strip()

    if not source or source not in AUTH:
        return jsonify({"ok": False, "error": "Пользователь не найден"}), 404

    if source == current_user:
        return jsonify({"ok": False, "error": "Нельзя импортировать свой набор"}), 400

    meta = get_user_meta(source)
    if not meta.get("shared"):
        return jsonify({"ok": False, "error": "Набор не является общим"}), 403

    imported = 0
    skipped = 0

    with lock:
        source_phones = users_phones.get(source, {})
        if current_user not in users_phones:
            users_phones[current_user] = {}
        target = users_phones[current_user]
        next_pos = len(target)

        for number, phone in source_phones.items():
            if number in target:
                skipped += 1
                continue
            target[number] = {
                "name": phone["name"],
                "ip": phone["ip"],
                "state": "В_покое",
                "time": "-",
                "peer": "",
                "duration": "00:00",
                "call_start": None,
                "ping": "?",
                "position": next_pos,
            }
            next_pos += 1
            imported += 1

    if imported:
        save_phones(current_user)
        broadcast_update()

    return jsonify({"ok": True, "imported": imported, "skipped": skipped})


def ping_once(ip: str):
    if not ip:
        return None

    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = ["ping", "-n", "1", "-w", "500", "-l", "1", ip]
            kwargs = {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
        else:
            cmd = ["ping", "-c", "1", "-W", "1", "-s", "1", ip]
            kwargs = {}

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            **kwargs
        )

        if result.returncode != 0:
            return None

        # Поиск времени ответа (RU/EN, Linux/Windows)
        match = re.search(r"(?:time|время)[=<]\s*(\d+)", result.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1))

        return 1
    except Exception:
        return None


def ping_loop() -> None:
    # Увеличиваем число воркеров до 100 для масштабируемости.
    # Это позволяет обрабатывать сотни пингов одновременно, не блокируя мониторинг.
    executor = ThreadPoolExecutor(max_workers=100)
    
    while True:
        snapshot = []
        now = time.time()
        any_changed = False
        
        with lock:
            for username, phones in users_phones.items():
                for number, phone in phones.items():
                    # Очистка зависших состояний "Снята_трубка", "Входящий_вызов", "Исходящий_вызов" (таймаут 60 сек)
                    if phone.get("state") in ["Снята_трубка", "Входящий_вызов", "Исходящий_вызов"] and phone.get("call_start"):
                        if now - phone["call_start"] > 60:
                            phone["state"] = "В_покое"
                            phone["call_start"] = None
                            phone["peer"] = ""
                            phone["duration"] = "00:00"
                            any_changed = True
                    
                    ip_addr = phone.get("ip", "").strip()
                    if ip_addr:
                        snapshot.append((username, number, ip_addr))

        def task(uname, num, ip_addr):
            latency = ping_once(ip_addr)
            with lock:
                if uname not in users_phones or num not in users_phones[uname]:
                    return False
                
                phone = users_phones[uname][num]
                old_ping = phone.get("ping")
                old_state = phone.get("state")

                if latency is None:
                    phone["ping_fail_count"] = phone.get("ping_fail_count", 0) + 1
                    phone["ping"] = "Недоступен"
                    if phone["ping_fail_count"] >= 3:
                        phone["state"] = "OFFLINE"
                        phone["call_start"] = None
                        phone["duration"] = "00:00"
                else:
                    phone["ping_fail_count"] = 0
                    phone["ping"] = f"{latency} ms"
                    if phone["state"] == "OFFLINE":
                        phone["state"] = "В_покое"
                
                return phone.get("ping") != old_ping or phone.get("state") != old_state

        if snapshot:
            # Распределяем запуск процессов во времени (shaping), чтобы избежать пиков CPU.
            # Для 2000 телефонов размазываем запуск пачки на ~10 секунд.
            futures = []
            delay = 10.0 / len(snapshot) if len(snapshot) > 50 else 0
            
            for p in snapshot:
                futures.append(executor.submit(task, *p))
                if delay > 0:
                    time.sleep(delay)
            
            # Собираем результаты и проверяем наличие изменений
            for f in futures:
                try:
                    if f.result():
                        any_changed = True
                except Exception:
                    pass

        if any_changed:
            broadcast_update()

        # Пауза перед следующим полным циклом мониторинга
        time.sleep(10)



if __name__ == "__main__":
    load_phones()
    threading.Thread(target=ping_loop, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=8000, debug=False)