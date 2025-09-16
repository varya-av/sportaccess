from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, jsonify, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import UniqueConstraint, inspect, text
from urllib.parse import parse_qsl
from datetime import datetime, timezone
import os, time, hashlib, hmac, json, pandas as pd, requests
import traceback

# =======================
# Конфиг / переменные
# =======================
BOT_TOKEN = os.getenv("BOT_TOKEN", "7971252908:AAGfTw5shz1qRmioIOh_PYNSzEDEsyEAmUI")
BOT_USERNAME = os.getenv("BOT_USERNAME", "SportCityKorolevBot")  # без @
ADMIN_TG_IDS = [s.strip() for s in os.getenv("ADMIN_TG_IDS", "532064703").split(",") if s.strip()]
TG_WEBHOOK_SECRET = os.getenv("TG_WEBHOOK_SECRET", "change-me")  # придумай свой и положи в Railway

# --- Показывать только выбранные площадки на карте ---
# Можно переключать через переменную окружения GROUND_WHITELIST_ONLY=0/1
GROUND_WHITELIST_ONLY = os.getenv("GROUND_WHITELIST_ONLY", "1") == "1"

# Белый список площадок (6 шт.)
GROUND_WHITELIST = [
    {
        "latitude": 55.918148, "longitude": 37.841446,
        "school_name": "МБОУ СОШ №5",
        "address": "Октябрьский б-р, д.33",
        "sport_types": None
    },
    {
        "latitude": 55.936521, "longitude": 37.836438,
        "school_name": "МБОУ Гимназия №5",
        "address": "Мкр. Юбилейный, ул. Тихонравова, д.24/1",
        "sport_types": None
    },
    {
        "latitude": 55.919891, "longitude": 37.820370,
        "school_name": "МБОУ СОШ №7",
        "address": "ул. Октябрьская, д.23",
        "sport_types": None
    },
    {
        "latitude": 55.928124, "longitude": 37.854357,
        "school_name": "МБОУ Лицей №4",
        "address": "Мкр. Юбилейный, ул. Нестеренко, д.31",
        "sport_types": None
    },
    {
        "latitude": 55.924124, "longitude": 37.835674,
        "school_name": "МБОУ Гимназия №17",
        "address": "ул. Сакко и Ванцетти, д.12А",
        "sport_types": None
    },
    {
        "latitude": 55.909873, "longitude": 37.872384,
        "school_name": "МБОУ Гимназия №18",
        "address": "пр-т Космонавтов, д.37Б",
        "sport_types": None
    },
]

app = Flask(__name__)
app.secret_key = os.urandom(32)

# для Telegram WebApp (iframe)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="None")

# =======================
# База
# =======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


def utcnow():
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tg_id = db.Column(db.String(50), unique=True, nullable=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    phone = db.Column(db.String(32))


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(10), nullable=False)   # YYYY-MM-DD
    time = db.Column(db.String(5), nullable=False)    # HH:MM
    comment = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=utcnow)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False, index=True)
    date = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(5), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    sport = db.Column(db.String(120))
    max_size = db.Column(db.Integer, default=10)
    is_open = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)


class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    role = db.Column(db.String(20), default='member')
    joined_at = db.Column(db.DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint('team_id', 'user_id', name='uniq_team_user'),)


def _ensure_db():
    try:
        with app.app_context():
            db.create_all()
            insp = inspect(db.engine)
            cols = [c['name'] for c in insp.get_columns('user')]
            if 'phone' not in cols:
                with db.engine.begin() as conn:
                    conn.execute(text('ALTER TABLE "user" ADD COLUMN phone VARCHAR(32)'))
    except Exception as e:
        print("DB init/migrate error:", e)


_ensure_db()

# =======================
# Утилиты
# =======================
def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return redirect(url_for('login'))
        if not u.tg_id or str(u.tg_id) not in ADMIN_TG_IDS:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def load_grounds():
    """
    Возвращает список площадок.
    Если включён режим белого списка (GROUND_WHITELIST_ONLY=1),
    не читаем Excel — возвращаем ровно 6 площадок из GROUND_WHITELIST.
    Иначе читаем Excel как раньше.
    """
    if GROUND_WHITELIST_ONLY:
        items = []
        for i, src in enumerate(GROUND_WHITELIST):
            items.append({
                "id": i,
                "latitude": float(src["latitude"]),
                "longitude": float(src["longitude"]),
                "school_name": src.get("school_name") or "",
                "address": src.get("address") or "",
                "sport_types": src.get("sport_types") or "",
            })
        return items

    # ---- ниже остаётся прежняя логика чтения Excel ----
    path = 'data/grounds.xlsx'
    if not os.path.exists(path):
        return []

    df = pd.read_excel(path).rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })
    for col in ['latitude', 'longitude', 'school_name', 'address', 'sport_types']:
        if col not in df.columns:
            df[col] = None
    df = df[['latitude', 'longitude', 'school_name', 'address', 'sport_types']]
    df['latitude'] = pd.to_numeric(df['latitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index
    return df.to_dict(orient='records')



def verify_telegram_auth(data: dict) -> bool:
    data = dict(data)
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    check_hash = data.pop('hash', '')
    data_check_string = '\n'.join(sorted(f"{k}={v}" for k, v in data.items()))
    calc = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, check_hash)


def verify_webapp_init_data(init_data: str) -> bool:
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    tg_hash = pairs.pop('hash', None)
    if not tg_hash:
        return False
    secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
    data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(pairs.items(), key=lambda x: x[0]))
    calc = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, tg_hash)

# =======================
# Ошибки (чтобы видеть причину 500)
# =======================
@app.errorhandler(500)
def err500(e):
    print("=== INTERNAL ERROR ===")
    traceback.print_exc()
    return render_template('error500.html', msg=str(e)), 500

# =======================
# Служебные
# =======================
@app.route('/health')
def health():
    return 'ok', 200


@app.route('/favicon.ico')
def favicon():
    static_path = os.path.join(app.root_path, 'static')
    ico_path = os.path.join(static_path, 'favicon.ico')
    if os.path.exists(ico_path):
        return send_from_directory(static_path, 'favicon.ico')
    return ('', 204)


@app.route('/')
def index():
    return redirect(url_for('webapp_entry'))

# =======================
# Аутентификация
# =======================
@app.route('/webapp')
def webapp_entry():
    return render_template('webapp.html')


@app.route('/tg_webapp_auth', methods=['POST'])
def tg_webapp_auth():
    init_data = request.form.get('init_data', '')
    if not init_data:
        return "no init_data", 400
    if not verify_webapp_init_data(init_data):
        return "forbidden", 403

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    user_json = pairs.get('user')
    if not user_json:
        return "no user in init_data", 400

    u = json.loads(user_json)
    tg_id = str(u.get('id'))
    user = User.query.filter_by(tg_id=tg_id).first()
    if not user:
        user = User(
            tg_id=tg_id,
            first_name=u.get('first_name'),
            last_name=u.get('last_name'),
            username=u.get('username')
        )
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    return jsonify(status='ok')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/tg_auth')
def tg_auth():
    data = request.args.to_dict()
    if not verify_telegram_auth(data):
        return "Ошибка авторизации через Telegram", 403
    tg_id = data['id']
    user = User.query.filter_by(tg_id=tg_id).first()
    if not user:
        user = User(
            tg_id=tg_id,
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            username=data.get('username')
        )
        db.session.add(user)
        db.session.commit()
    session['user_id'] = user.id
    return redirect(url_for('main'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# =======================
# Телефон через чат-бота
# =======================
@app.route('/phone')
def phone_page():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if user.phone:
        nxt = request.args.get('next') or 'main'
        return redirect(nxt) if nxt.startswith('/') else redirect(url_for('main'))

    start_param = "sendphone"
    start_link = f"https://t.me/{BOT_USERNAME}?start={start_param}"
    check_url = url_for('phone_check', _external=False)
    return render_template('phone.html', user=user, start_link=start_link, check_url=check_url)


@app.route('/phone/check')
def phone_check():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    user = User.query.get(user.id)
    if user.phone:
        flash('Телефон сохранён.')
        nxt = request.args.get('next') or url_for('main')
        return redirect(nxt)
    flash('Телефон пока не получен. Проверьте, что отправили контакт в чате бота.')
    return redirect(url_for('phone_page'))

# ===== Telegram webhook (для кнопки "Отправить номер")
def _tg_api(method: str, **params):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    resp = requests.post(url, data=params, timeout=15)
    return resp.json()


@app.route('/tg/set_webhook')
def tg_set_webhook():
    if request.args.get('secret') != TG_WEBHOOK_SECRET:
        abort(403)
    url = request.url_root.rstrip('/') + '/tg/webhook'
    res = _tg_api('setWebhook', url=url)
    return jsonify(res)


@app.route('/tg/get_webhook_info')
def tg_get_webhook_info():
    if request.args.get('secret') != TG_WEBHOOK_SECRET:
        abort(403)
    return jsonify(_tg_api('getWebhookInfo'))


@app.route('/tg/webhook', methods=['POST'])
def tg_webhook():
    data = request.get_json(force=True, silent=True) or {}
    msg = data.get('message') or data.get('edited_message') or {}
    chat = msg.get('chat') or {}
    from_user = msg.get('from') or {}

    # /start с deep-link ?start=sendphone -> показать клавиатуру с запросом контакта
    if 'text' in msg and msg.get('text', '').startswith('/start'):
        text = msg['text']
        if 'sendphone' in text:
            kb = {
                "keyboard": [[{"text": "📲 Отправить номер", "request_contact": True}]],
                "resize_keyboard": True,
                "one_time_keyboard": True
            }
            _tg_api('sendMessage',
                    chat_id=chat.get('id'),
                    text="Нажмите кнопку ниже, чтобы отправить номер телефона:",
                    reply_markup=json.dumps(kb))
        else:
            _tg_api('sendMessage',
                    chat_id=chat.get('id'),
                    text="Привет! Откройте мини-приложение из меню бота.")
        return jsonify(ok=True)

    # пришёл контакт — сохраним
    contact = msg.get('contact')
    if contact and str(contact.get('user_id')) == str(from_user.get('id')):
        tg_id = str(from_user.get('id'))
        phone_raw = contact.get('phone_number', '')
        phone = phone_raw if phone_raw.startswith('+') else '+' + phone_raw

        user = User.query.filter_by(tg_id=tg_id).first()
        if not user:
            user = User(tg_id=tg_id,
                        first_name=from_user.get('first_name'),
                        last_name=from_user.get('last_name'),
                        username=from_user.get('username'))
            db.session.add(user)
        user.phone = phone
        db.session.commit()

        _tg_api('sendMessage',
                chat_id=chat.get('id'),
                text=f"Спасибо! Номер {phone} сохранён.\nМожно вернуться в мини-приложение.")
        return jsonify(ok=True)

    return jsonify(ok=True)

# =======================
# Основной UI
# =======================
@app.route('/main')
def main():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if not user.phone:
        return redirect(url_for('phone_page', next=url_for('main')))
    grounds = load_grounds()
    is_admin = bool(user.tg_id and str(user.tg_id) in ADMIN_TG_IDS)
    return render_template('main.html', user=user, grounds=grounds, is_admin=is_admin)


@app.route('/book/<int:ground_id>', methods=['GET', 'POST'])
def book(ground_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    if not user.phone:
        return redirect(url_for('phone_page', next=url_for('book', ground_id=ground_id)))

    grounds = load_grounds()
    ground = next((gr for gr in grounds if gr['id'] == ground_id), None)
    if not ground:
        abort(404, 'Площадка не найдена')

    open_teams = Team.query.filter_by(ground_id=ground_id, is_open=True).order_by(Team.date, Team.time).all()
    team_ids = [t.id for t in open_teams]
    members_map = {tid: 0 for tid in team_ids}
    if team_ids:
        for tm in TeamMember.query.filter(TeamMember.team_id.in_(team_ids)).all():
            members_map[tm.team_id] = members_map.get(tm.team_id, 0) + 1

    open_items = [{
        "id": t.id,
        "name": t.name,
        "date": t.date,
        "time": t.time,
        "sport": t.sport or (ground.get('sport_types') or ''),
        "max_size": t.max_size,
        "members": members_map.get(t.id, 0),
        "is_open": t.is_open
    } for t in open_teams]

    if request.method == 'POST':
        mode = request.form.get('mode', 'solo')
        date = (request.form.get('date') or '').strip()
        tm = (request.form.get('time') or '').strip()
        comment = (request.form.get('comment') or '').strip()
        if not date or not tm:
            flash('Укажите дату и время.')
            return render_template('book.html', user=user, ground=ground, open_items=open_items)

        if mode == 'team_create':
            team_name = (request.form.get('team_name') or '').strip() or f"Команда {user.first_name or user.username or user.id}"
            max_size = request.form.get('max_size', '10')
            try:
                max_size = max(2, min(50, int(max_size)))
            except ValueError:
                max_size = 10
            team = Team(owner_id=user.id, ground_id=ground_id, date=date, time=tm,
                        name=team_name, sport=(ground.get('sport_types') or None),
                        max_size=max_size, is_open=True)
            db.session.add(team)
            db.session.flush()
            db.session.add(TeamMember(team_id=team.id, user_id=user.id, role='owner'))
            db.session.commit()
            flash('Команда создана.')
            return redirect(url_for('team_detail', team_id=team.id))

        b = Booking(user_id=user.id, ground_id=ground_id, date=date, time=tm, comment=comment)
        db.session.add(b)
        db.session.commit()
        flash('Запись создана.')
        return redirect(url_for('my_bookings'))

    return render_template('book.html', user=user, ground=ground, open_items=open_items)


@app.route('/my-bookings')
def my_bookings():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    bookings = Booking.query.filter_by(user_id=user.id).order_by(Booking.date, Booking.time).all()
    grounds = {gr['id']: gr for gr in load_grounds()}
    items = [{
        'id': b.id,
        'date': b.date,
        'time': b.time,
        'comment': b.comment,
        'school_name': grounds.get(b.ground_id, {}).get('school_name', '—'),
        'address': grounds.get(b.ground_id, {}).get('address', '—'),
        'sport_types': grounds.get(b.ground_id, {}).get('sport_types', '—'),
    } for b in bookings]
    return render_template('my_bookings.html', user=user, items=items)


@app.route('/cancel/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user.id:
        abort(403)
    db.session.delete(b)
    db.session.commit()
    flash('Запись отменена.')
    return redirect(url_for('my_bookings'))

# =======================
# Команды
# =======================
@app.route('/teams')
def teams_list():
    ground_id = request.args.get('ground_id', type=int)
    date = request.args.get('date', type=str)
    q = Team.query.filter_by(is_open=True)
    if ground_id is not None:
        q = q.filter(Team.ground_id == ground_id)
    if date:
        q = q.filter(Team.date == date)
    teams = q.order_by(Team.date, Team.time).all()
    grounds = {gr['id']: gr for gr in load_grounds()}
    items = []
    for t in teams:
        gr = grounds.get(t.ground_id, {})
        members = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id, 'name': t.name, 'date': t.date, 'time': t.time,
            'sport': t.sport or gr.get('sport_types', '—'),
            'max_size': t.max_size, 'members': members,
            'school_name': gr.get('school_name', '—'), 'address': gr.get('address', '—'),
            'is_open': t.is_open
        })
    return render_template('teams_list.html', items=items)


@app.route('/my-teams')
def my_teams():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    t_ids = [tm.team_id for tm in TeamMember.query.filter_by(user_id=user.id).all()]
    teams = Team.query.filter(Team.id.in_(t_ids)).order_by(Team.date, Team.time).all() if t_ids else []
    grounds = {gr['id']: gr for gr in load_grounds()}
    items = []
    for t in teams:
        gr = grounds.get(t.ground_id, {})
        members = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id, 'name': t.name, 'date': t.date, 'time': t.time,
            'sport': t.sport or gr.get('sport_types', '—'),
            'max_size': t.max_size, 'members': members,
            'school_name': gr.get('school_name', '—'), 'address': gr.get('address', '—'),
            'is_open': t.is_open
        })
    return render_template('my_teams.html', items=items)


@app.route('/teams/<int:team_id>')
def team_detail(team_id):
    t = Team.query.get_or_404(team_id)
    user = current_user()
    grounds = {gr['id']: gr for gr in load_grounds()}
    gr = grounds.get(t.ground_id, {})
    members = TeamMember.query.filter_by(team_id=t.id).all()
    users = {u.id: u for u in User.query.filter(User.id.in_([m.user_id for m in members])).all()}
    mlist = [{
        'user_id': m.user_id,
        'name': (f"{(users.get(m.user_id).first_name or '')} {(users.get(m.user_id).last_name or '')}".strip()
                 if users.get(m.user_id) else f"ID {m.user_id}"),
        'username': (users.get(m.user_id).username if users.get(m.user_id) else ''),
        'role': m.role
    } for m in members]
    is_owner = bool(user and user.id == t.owner_id)
    i_am_member = bool(user and TeamMember.query.filter_by(team_id=t.id, user_id=user.id).first())
    return render_template('team_detail.html',
                           team=t, gnd=gr, members=mlist,
                           member_count=len(members), is_owner=is_owner, i_am_member=i_am_member)


@app.route('/teams/<int:team_id>/join', methods=['POST'])
def team_join(team_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    t = Team.query.get_or_404(team_id)
    if not t.is_open:
        flash('Команда закрыта для новых участников.')
        return redirect(url_for('team_detail', team_id=team_id))
    if TeamMember.query.filter_by(team_id=team_id, user_id=user.id).first():
        flash('Вы уже в этой команде.')
        return redirect(url_for('team_detail', team_id=team_id))
    if TeamMember.query.filter_by(team_id=team_id).count() >= t.max_size:
        flash('Команда уже набрана.')
        return redirect(url_for('team_detail', team_id=team_id))
    db.session.add(TeamMember(team_id=team_id, user_id=user.id, role='member'))
    db.session.commit()
    flash('Вы присоединились к команде.')
    return redirect(url_for('team_detail', team_id=team_id))


@app.route('/teams/<int:team_id>/leave', methods=['POST'])
def team_leave(team_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    t = Team.query.get_or_404(team_id)
    tm = TeamMember.query.filter_by(team_id=team_id, user_id=user.id).first()
    if not tm:
        flash('Вы не в этой команде.')
        return redirect(url_for('team_detail', team_id=team_id))
    if t.owner_id == user.id:
        flash('Вы владелец. Сначала закройте набор или передайте владение.')
        return redirect(url_for('team_detail', team_id=team_id))
    db.session.delete(tm)
    db.session.commit()
    flash('Вы вышли из команды.')
    return redirect(url_for('team_detail', team_id=team_id))


@app.route('/teams/<int:team_id>/close', methods=['POST'])
def team_close(team_id):
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    t = Team.query.get_or_404(team_id)
    if t.owner_id != user.id:
        abort(403)
    t.is_open = False
    db.session.commit()
    flash('Набор в команду закрыт.')
    return redirect(url_for('team_detail', team_id=team_id))

# =======================
# Админка
# =======================
@app.route('/admin')
@admin_required
def admin_home():
    return redirect(url_for('admin_users'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    bookings = Booking.query.order_by(Booking.date, Booking.time).all()
    users = {u.id: u for u in User.query.all()}
    grounds = {gr['id']: gr for gr in load_grounds()}
    items = []
    for b in bookings:
        u = users.get(b.user_id)
        gr = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id, 'date': b.date, 'time': b.time, 'comment': b.comment,
            'user_id': b.user_id,
            'user_name': f"{(u.first_name or '')} {(u.last_name or '')}".strip() if u else '—',
            'username': u.username if u else '—',
            'tg_id': u.tg_id if u else '—',
            'school_name': gr.get('school_name', '—'),
            'address': gr.get('address', '—'),
            'sport_types': gr.get('sport_types', '—'),
        })
    return render_template('admin_bookings.html', items=items)


@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    u = User.query.get_or_404(user_id)
    bks = Booking.query.filter_by(user_id=user_id).order_by(Booking.date, Booking.time).all()
    grounds = {gr['id']: gr for gr in load_grounds()}
    items = []
    for b in bks:
        gr = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id, 'date': b.date, 'time': b.time, 'comment': b.comment,
            'school_name': gr.get('school_name', '—'),
            'address': gr.get('address', '—'),
            'sport_types': gr.get('sport_types', '—'),
        })
    return render_template('admin_user.html', u=u, items=items)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
