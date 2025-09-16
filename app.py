from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, jsonify, flash, send_from_directory, g
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import UniqueConstraint, inspect, text
import os, time, hashlib, hmac, json, pandas as pd
from urllib.parse import parse_qsl
from datetime import datetime
import requests

# =======================
#  Секреты / переменные
# =======================
BOT_TOKEN         = os.getenv("BOT_TOKEN", "")
BOT_USERNAME      = os.getenv("BOT_USERNAME", "SportCityKorolevBot")  # без @
ADMIN_TG_IDS      = [s.strip() for s in os.getenv("ADMIN_TG_IDS", "532064703").split(",") if s.strip()]
TG_WEBHOOK_SECRET = os.getenv("TG_WEBHOOK_SECRET", "set-me")

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

# =======================
#  База
# =======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    tg_id      = db.Column(db.String(50), unique=True, nullable=True)
    first_name = db.Column(db.String(100))
    last_name  = db.Column(db.String(100))
    username   = db.Column(db.String(100))
    phone      = db.Column(db.String(32))

class Booking(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False)
    date      = db.Column(db.String(10), nullable=False)  # YYYY-MM-DD
    time      = db.Column(db.String(5),  nullable=False)  # HH:MM
    comment   = db.Column(db.String(500))
    created_at= db.Column(db.DateTime, default=datetime.utcnow)

class Team(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    owner_id  = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False, index=True)
    date      = db.Column(db.String(10), nullable=False)
    time      = db.Column(db.String(5),  nullable=False)
    name      = db.Column(db.String(120), nullable=False)
    sport     = db.Column(db.String(120))
    max_size  = db.Column(db.Integer, default=10)
    is_open   = db.Column(db.Boolean, default=True)
    created_at= db.Column(db.DateTime, default=datetime.utcnow)

class TeamMember(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    team_id  = db.Column(db.Integer, nullable=False, index=True)
    user_id  = db.Column(db.Integer, nullable=False, index=True)
    role     = db.Column(db.String(20), default='member')  # owner/member
    joined_at= db.Column(db.DateTime, default=datetime.utcnow)
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
#  Утилиты/декораторы
# =======================
def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None

def login_required(view):
    @wraps(view)
    def w(*a, **kw):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return view(*a, **kw)
    return w

def phone_required(view):
    @wraps(view)
    def w(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for('login'))
        if not u.phone:
            nxt = request.full_path if request.full_path else request.path
            return redirect(url_for('phone', next=nxt))
        return view(*a, **kw)
    return w

def admin_required(view):
    @wraps(view)
    def w(*a, **kw):
        u = current_user()
        if not u:
            return redirect(url_for('login'))
        if not u.tg_id or str(u.tg_id) not in ADMIN_TG_IDS:
            abort(403)
        g.admin = u
        return view(*a, **kw)
    return w

def load_grounds():
    path = 'data/grounds.xlsx'
    if not os.path.exists(path):
        abort(500, f'Файл {path} не найден на сервере')
    df = pd.read_excel(path).rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })
    for col in ['latitude','longitude','school_name','address','sport_types']:
        if col not in df.columns:
            df[col] = None
    df = df[['latitude','longitude','school_name','address','sport_types']]
    df['latitude']  = pd.to_numeric(df['latitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df.dropna(subset=['latitude','longitude'], inplace=True)
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
#  Служебные
# =======================
@app.route('/health')
def health(): return 'ok', 200

@app.route('/favicon.ico')
def favicon():
    static_path = os.path.join(app.root_path, 'static')
    ico_path = os.path.join(static_path, 'favicon.ico')
    if os.path.exists(ico_path):
        return send_from_directory(static_path, 'favicon.ico')
    return ('', 204)

@app.route('/')
def index(): return redirect(url_for('webapp_entry'))

# =======================
#  Аутентификация
# =======================
@app.route('/webapp')
def webapp_entry():
    return render_template('webapp.html')

@app.route('/tg_webapp_auth', methods=['POST'])
def tg_webapp_auth():
    init_data = request.form.get('init_data', '')
    if not init_data: return "no init_data", 400
    if not verify_webapp_init_data(init_data): return "forbidden", 403

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    user_json = pairs.get('user')
    if not user_json: return "no user", 400

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
def login(): return render_template('login.html')

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
#  Телефон (обязателен)
# =======================
@app.route('/phone')
@login_required
def phone():
    u = current_user()
    if u.phone:
        return redirect(request.args.get('next') or url_for('main'))
    deep_link = f"https://t.me/{BOT_USERNAME}?start=sendphone"
    return render_template('phone.html', deep_link=deep_link)

@app.route('/phone/check')
@login_required
def phone_check():
    u = current_user()
    has = bool(u.phone)
    return jsonify(ok=True, has_phone=has, next=request.args.get('next') or url_for('main'))

# =======================
#  Главная / карта
# =======================
@app.route('/main')
@login_required
def main():
    user = current_user()
    # Просим телефон ОДИН РАЗ сразу после входа
    if not user.phone:
        return redirect(url_for('phone', next=url_for('main')))
    grounds = load_grounds()
    is_admin = bool(user.tg_id and str(user.tg_id) in ADMIN_TG_IDS)
    return render_template('main.html', user=user, grounds=grounds, is_admin=is_admin)

# =======================
#  Бронирования
# =======================
@app.route('/book/<int:ground_id>', methods=['GET', 'POST'])
@login_required
@phone_required
def book(ground_id):
    user = current_user()
    grounds = load_grounds()
    ground = next((g for g in grounds if g['id'] == ground_id), None)
    if not ground: abort(404, 'Площадка не найдена')

    open_teams = Team.query.filter_by(ground_id=ground_id, is_open=True).order_by(Team.date, Team.time).all()
    team_ids = [t.id for t in open_teams]
    members_map = {tid: 0 for tid in team_ids}
    if team_ids:
        for tm in TeamMember.query.filter(TeamMember.team_id.in_(team_ids)).all():
            members_map[tm.team_id] = members_map.get(tm.team_id, 0) + 1
    open_items = [{
        "id": t.id, "name": t.name, "date": t.date, "time": t.time,
        "sport": t.sport or (ground.get('sport_types') or ''), "max_size": t.max_size,
        "members": members_map.get(t.id, 0), "is_open": t.is_open
    } for t in open_teams]

    if request.method == 'POST':
        mode    = request.form.get('mode', 'solo')
        date    = request.form.get('date', '').strip()
        tm      = request.form.get('time', '').strip()
        comment = request.form.get('comment', '').strip()
        if not date or not tm:
            flash('Укажите дату и время.')
            return render_template('book.html', user=user, ground=ground, open_items=open_items)

        if mode == 'team_create':
            team_name = (request.form.get('team_name') or '').strip() or f"Команда {user.first_name or user.username or user.id}"
            max_size  = request.form.get('max_size', '10')
            try: max_size = max(2, min(50, int(max_size)))
            except: max_size = 10
            team = Team(owner_id=user.id, ground_id=ground_id, date=date, time=tm,
                        name=team_name, sport=(ground.get('sport_types') or None),
                        max_size=max_size, is_open=True)
            db.session.add(team); db.session.flush()
            db.session.add(TeamMember(team_id=team.id, user_id=user.id, role='owner'))
            db.session.commit()
            flash('Команда создана.')
            return redirect(url_for('team_detail', team_id=team.id))

        b = Booking(user_id=user.id, ground_id=ground_id, date=date, time=tm, comment=comment)
        db.session.add(b); db.session.commit()
        flash('Запись создана.')
        return redirect(url_for('my_bookings'))

    return render_template('book.html', user=user, ground=ground, open_items=open_items)

@app.route('/my-bookings')
@login_required
def my_bookings():
    user = current_user()
    bookings = Booking.query.filter_by(user_id=user.id).order_by(Booking.date, Booking.time).all()
    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for b in bookings:
        gnd = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id, 'date': b.date, 'time': b.time, 'comment': b.comment,
            'school_name': gnd.get('school_name', '—'), 'address': gnd.get('address', '—'),
            'sport_types': gnd.get('sport_types', '—'),
        })
    return render_template('my_bookings.html', user=user, items=items)

@app.route('/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    user = current_user()
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user.id: abort(403)
    db.session.delete(b); db.session.commit()
    flash('Запись отменена.')
    return redirect(url_for('my_bookings'))

# =======================
#  Команды
# =======================
@app.route('/teams')
@login_required
def teams_list():
    ground_id = request.args.get('ground_id', type=int)
    date      = request.args.get('date', type=str)
    q = Team.query.filter_by(is_open=True)
    if ground_id is not None: q = q.filter(Team.ground_id == ground_id)
    if date: q = q.filter(Team.date == date)
    teams = q.order_by(Team.date, Team.time).all()
    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for t in teams:
        gnd = grounds.get(t.ground_id, {})
        member_count = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id, 'name': t.name, 'date': t.date, 'time': t.time,
            'sport': t.sport or gnd.get('sport_types', '—'), 'max_size': t.max_size,
            'members': member_count, 'school_name': gnd.get('school_name', '—'),
            'address': gnd.get('address', '—'), 'is_open': t.is_open
        })
    return render_template('teams_list.html', items=items)

@app.route('/my-teams')
@login_required
def my_teams():
    user = current_user()
    t_ids = [tm.team_id for tm in TeamMember.query.filter_by(user_id=user.id).all()]
    teams = Team.query.filter(Team.id.in_(t_ids)).order_by(Team.date, Team.time).all() if t_ids else []
    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for t in teams:
        gnd = grounds.get(t.ground_id, {})
        members = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id, 'name': t.name, 'date': t.date, 'time': t.time,
            'sport': t.sport or gnd.get('sport_types', '—'), 'max_size': t.max_size,
            'members': members, 'school_name': gnd.get('school_name', '—'),
            'address': gnd.get('address', '—'), 'is_open': t.is_open
        })
    return render_template('my_teams.html', items=items)

@app.route('/teams/<int:team_id>')
@login_required
def team_detail(team_id):
    t = Team.query.get_or_404(team_id)
    user = current_user()
    grounds = {g['id']: g for g in load_grounds()}
    gnd = grounds.get(t.ground_id, {})
    members = TeamMember.query.filter_by(team_id=t.id).all()
    users = {u.id: u for u in User.query.filter(User.id.in_([m.user_id for m in members])).all()}
    mlist = []
    for m in members:
        u = users.get(m.user_id)
        mlist.append({
            'user_id': m.user_id,
            'name': f"{(u.first_name or '')} {(u.last_name or '')}".strip() if u else f"ID {m.user_id}",
            'username': u.username if u else '',
            'role': m.role
        })
    is_owner    = bool(user and user.id == t.owner_id)
    i_am_member = bool(user and TeamMember.query.filter_by(team_id=t.id, user_id=user.id).first())
    member_count= len(members)
    return render_template('team_detail.html', team=t, gnd=gnd, members=mlist,
                           member_count=member_count, is_owner=is_owner, i_am_member=i_am_member)

@app.route('/teams/<int:team_id>/join', methods=['POST'])
@login_required
def team_join(team_id):
    user = current_user()
    t = Team.query.get_or_404(team_id)
    if not t.is_open:
        flash('Команда закрыта.'); return redirect(url_for('team_detail', team_id=team_id))
    if TeamMember.query.filter_by(team_id=team_id, user_id=user.id).first():
        flash('Вы уже в команде.'); return redirect(url_for('team_detail', team_id=team_id))
    if TeamMember.query.filter_by(team_id=team_id).count() >= t.max_size:
        flash('Команда уже набрана.'); return redirect(url_for('team_detail', team_id=team_id))
    db.session.add(TeamMember(team_id=team_id, user_id=user.id, role='member')); db.session.commit()
    flash('Вы присоединились.'); return redirect(url_for('team_detail', team_id=team_id))

@app.route('/teams/<int:team_id>/leave', methods=['POST'])
@login_required
def team_leave(team_id):
    user = current_user()
    t = Team.query.get_or_404(team_id)
    tm = TeamMember.query.filter_by(team_id=team_id, user_id=user.id).first()
    if not tm: flash('Вы не в команде.'); return redirect(url_for('team_detail', team_id=team_id))
    if t.owner_id == user.id:
        flash('Вы владелец. Сначала закройте набор или передайте владение.')
        return redirect(url_for('team_detail', team_id=team_id))
    db.session.delete(tm); db.session.commit()
    flash('Вы вышли.'); return redirect(url_for('team_detail', team_id=team_id))

@app.route('/teams/<int:team_id>/close', methods=['POST'])
@login_required
def team_close(team_id):
    user = current_user()
    t = Team.query.get_or_404(team_id)
    if t.owner_id != user.id: abort(403)
    t.is_open = False; db.session.commit()
    flash('Набор закрыт.'); return redirect(url_for('team_detail', team_id=team_id))

# =======================
#  Админ
# =======================
@app.route('/admin'); @app.route('/admin/')
@admin_required
def admin_home(): return redirect(url_for('admin_users'))

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
    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for b in bookings:
        u = users.get(b.user_id); g = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id, 'date': b.date, 'time': b.time, 'comment': b.comment,
            'user_id': b.user_id, 'user_name': f"{(u.first_name or '')} {(u.last_name or '')}".strip() if u else '—',
            'username': u.username if u else '—', 'tg_id': u.tg_id if u else '—',
            'school_name': g.get('school_name', '—'), 'address': g.get('address', '—'),
            'sport_types': g.get('sport_types', '—'),
        })
    return render_template('admin_bookings.html', items=items)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    u = User.query.get_or_404(user_id)
    bks = Booking.query.filter_by(user_id=user_id).order_by(Booking.date, Booking.time).all()
    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for b in bks:
        g = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id, 'date': b.date, 'time': b.time, 'comment': b.comment,
            'school_name': g.get('school_name', '—'), 'address': g.get('address', '—'),
            'sport_types': g.get('sport_types', '—'),
        })
    return render_template('admin_user.html', u=u, items=items)

# =======================
#  Телеграм вебхук (номер телефона)
# =======================
def tg_api(method, **params):
    return requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/{method}", json=params, timeout=10).json()

@app.route('/tg/set_webhook')
def tg_set_webhook():
    if request.args.get('secret') != TG_WEBHOOK_SECRET: abort(403)
    url = request.url_root.rstrip('/') + '/tg/webhook'
    res = tg_api('setWebhook', url=url, allowed_updates=["message","callback_query"])
    return jsonify(res)

@app.route('/tg/get_webhook_info')
def tg_get_webhook_info():
    if request.args.get('secret') != TG_WEBHOOK_SECRET: abort(403)
    return jsonify(tg_api('getWebhookInfo'))

@app.route('/tg/webhook', methods=['POST'])
def tg_webhook():
    upd = request.get_json(force=True, silent=True) or {}
    msg = upd.get('message') or {}
    text = msg.get('text') or ""
    chat = msg.get('chat') or {}
    from_user = msg.get('from') or {}

    if text == "/start sendphone":
        kb = {"keyboard":[[{"text":"📲 Отправить номер","request_contact":True}]],
              "resize_keyboard":True,"one_time_keyboard":True}
        tg_api("sendMessage", chat_id=chat["id"],
               text="Нажмите «📲 Отправить номер», чтобы подтвердить телефон.",
               reply_markup=kb)
        return jsonify(ok=True)

    contact = msg.get('contact')
    if contact and str(contact.get('user_id')) == str(from_user.get('id')):
        u = User.query.filter_by(tg_id=str(from_user.get('id'))).first()
        if not u:
            u = User(tg_id=str(from_user.get('id')),
                     first_name=from_user.get('first_name'),
                     last_name=from_user.get('last_name'),
                     username=from_user.get('username'))
            db.session.add(u)
        u.phone = contact.get('phone_number')
        db.session.commit()
        tg_api("sendMessage", chat_id=chat["id"], text="Спасибо! Телефон сохранён. Можете вернуться в мини-приложение.")
        return jsonify(ok=True)

    # Небольшая помощь пользователю
    if text == "/start" or text.startswith("/start"):
        tg_api("sendMessage", chat_id=chat["id"],
               text="Это служебный бот SportCity. Откройте мини-приложение из кнопки в меню.\nЧтобы прислать телефон: /start sendphone")
    return jsonify(ok=True)

# =======================
#  Ошибки/отладка
# =======================
@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, message="Доступ запрещён"), 403

@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, message="Страница не найдена"), 404

@app.route('/debug/whoami')
@login_required
def whoami():
    u = current_user()
    return jsonify(
        user_id=u.id, tg_id=u.tg_id, username=u.username, phone=u.phone,
        is_admin=bool(u.tg_id and str(u.tg_id) in ADMIN_TG_IDS)
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
