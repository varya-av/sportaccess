from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, jsonify, flash, send_from_directory, g
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import UniqueConstraint
import os, time, hashlib, hmac, json, pandas as pd
from urllib.parse import parse_qsl
from datetime import datetime

# =======================
#  Секреты / настройки
# =======================

# По твоей просьбе — токен оставлен в коде (можно переопределить переменной окружения BOT_TOKEN)
BOT_TOKEN = os.getenv("BOT_TOKEN", "7971252908:AAGfTw5shz1qRmioIOh_PYNSzEDEsyEAmUI")

# Белый список админов по Telegram user id (через запятую). По умолчанию — твой ID из логов.
ADMIN_TG_IDS = [s.strip() for s in os.getenv("ADMIN_TG_IDS", "532064703").split(",") if s.strip()]

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Фикс для Telegram Web (iframe): куки должны быть Secure + SameSite=None
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
)

# =======================
#  База данных
# =======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tg_id = db.Column(db.String(50), unique=True, nullable=True)  # Telegram user id
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(10), nullable=False)   # YYYY-MM-DD
    time = db.Column(db.String(5), nullable=False)    # HH:MM
    comment = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, nullable=False, index=True)
    ground_id = db.Column(db.Integer, nullable=False, index=True)
    date = db.Column(db.String(10), nullable=False)   # YYYY-MM-DD
    time = db.Column(db.String(5), nullable=False)    # HH:MM
    name = db.Column(db.String(120), nullable=False)
    sport = db.Column(db.String(120))
    max_size = db.Column(db.Integer, default=10)
    is_open = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    role = db.Column(db.String(20), default='member')  # owner/member
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('team_id', 'user_id', name='uniq_team_user'),
    )

# =======================
#  Утилиты
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
        g.admin = u
        return view(*args, **kwargs)
    return wrapper


def load_grounds():
    """Читает Excel с площадками и готовит список словарей."""
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

    for col in ['latitude', 'longitude', 'school_name', 'address', 'sport_types']:
        if col not in df.columns:
            df[col] = None
    df = df[['latitude', 'longitude', 'school_name', 'address', 'sport_types']]

    # Коммы -> точки и в float
    df['latitude']  = pd.to_numeric(df['latitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')

    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index
    return df.to_dict(orient='records')


def verify_telegram_auth(data: dict) -> bool:
    """Проверка подписи для Login Widget (браузерный OAuth)."""
    data = dict(data)  # не мутируем исходный dict
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False

    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    check_hash = data.pop('hash', '')
    data_check_string = '\n'.join(sorted(f"{k}={v}" for k, v in data.items()))
    calc = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, check_hash)


def verify_webapp_init_data(init_data: str) -> bool:
    """Проверка подписи initData для Telegram WebApp."""
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    tg_hash = pairs.pop('hash', None)
    if not tg_hash:
        return False

    secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
    data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(pairs.items(), key=lambda x: x[0]))
    calc = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, tg_hash)

# =======================
#  Служебные роуты
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
    # удобнее сразу на мини-приложение
    return redirect(url_for('webapp_entry'))

# =======================
#  Аутентификация
# =======================

@app.route('/webapp')
def webapp_entry():
    """Страница WebApp (встроенный браузер Telegram)."""
    return render_template('webapp.html')


@app.route('/tg_webapp_auth', methods=['POST'])
def tg_webapp_auth():
    """Приём initData из Telegram WebApp, проверка подписи и создание сессии."""
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
    """Резервный вход (браузерный Telegram Login Widget)."""
    return render_template('login.html')


@app.route('/tg_auth')
def tg_auth():
    """Callback от Login Widget: проверка подписи и создание сессии."""
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
#  Основной UI
# =======================

@app.route('/main')
def main():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    grounds = load_grounds()
    is_admin = bool(user.tg_id and str(user.tg_id) in ADMIN_TG_IDS)
    return render_template('main.html', user=user, grounds=grounds, is_admin=is_admin)


@app.route('/book/<int:ground_id>', methods=['GET', 'POST'])
def book(ground_id):
    """Страница записи + при желании создание команды."""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    grounds = load_grounds()
    ground = next((g for g in grounds if g['id'] == ground_id), None)
    if not ground:
        abort(404, 'Площадка не найдена')

    # Открытые команды на этой площадке (для блока "Присоединиться")
    teams_q = Team.query.filter_by(ground_id=ground_id, is_open=True).order_by(Team.date, Team.time)
    open_teams = teams_q.all()

    # Счётчики участников по командам
    team_ids = [t.id for t in open_teams]
    members_map = {tid: 0 for tid in team_ids}
    if team_ids:
        for tm in TeamMember.query.filter(TeamMember.team_id.in_(team_ids)).all():
            members_map[tm.team_id] = members_map.get(tm.team_id, 0) + 1

    open_items = []
    for t in open_teams:
        open_items.append({
            "id": t.id,
            "name": t.name,
            "date": t.date,
            "time": t.time,
            "sport": t.sport or (ground.get('sport_types') or ''),
            "max_size": t.max_size,
            "members": members_map.get(t.id, 0),
            "is_open": t.is_open
        })

    if request.method == 'POST':
        mode = request.form.get('mode', 'solo')  # solo | team_create
        date = request.form.get('date', '').strip()
        tm = request.form.get('time', '').strip()
        comment = request.form.get('comment', '').strip()

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

            team = Team(
                owner_id=user.id,
                ground_id=ground_id,
                date=date,
                time=tm,
                name=team_name,
                sport=(ground.get('sport_types') or None),
                max_size=max_size,
                is_open=True
            )
            db.session.add(team)
            db.session.flush()  # нужен team.id

            db.session.add(TeamMember(team_id=team.id, user_id=user.id, role='owner'))
            db.session.commit()

            flash('Команда создана. Пригласите участников или позвольте им присоединиться.')
            return redirect(url_for('team_detail', team_id=team.id))

        # Личная запись
        b = Booking(user_id=user.id, ground_id=ground_id, date=date, time=tm, comment=comment)
        db.session.add(b)
        db.session.commit()
        flash('Запись создана.')
        return redirect(url_for('my_bookings'))

    # GET
    return render_template('book.html', user=user, ground=ground, open_items=open_items)


@app.route('/my-bookings')
def my_bookings():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    bookings = Booking.query.filter_by(user_id=user_id).order_by(Booking.date, Booking.time).all()
    grounds = {g['id']: g for g in load_grounds()}

    items = []
    for b in bookings:
        gnd = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id,
            'date': b.date,
            'time': b.time,
            'comment': b.comment,
            'school_name': gnd.get('school_name', '—'),
            'address': gnd.get('address', '—'),
            'sport_types': gnd.get('sport_types', '—'),
        })

    return render_template('my_bookings.html', user=user, items=items)


@app.route('/cancel/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    b = Booking.query.get_or_404(booking_id)
    if b.user_id != user_id:
        abort(403)

    db.session.delete(b)
    db.session.commit()
    flash('Запись отменена.')
    return redirect(url_for('my_bookings'))

# =======================
#  Команды: списки/детали/действия
# =======================

@app.route('/teams')
def teams_list():
    """Список всех открытых команд (фильтры по площадке/дате опционально)."""
    ground_id = request.args.get('ground_id', type=int)
    date = request.args.get('date', type=str)

    q = Team.query.filter_by(is_open=True)
    if ground_id is not None:
        q = q.filter(Team.ground_id == ground_id)
    if date:
        q = q.filter(Team.date == date)

    teams = q.order_by(Team.date, Team.time).all()

    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for t in teams:
        gnd = grounds.get(t.ground_id, {})
        member_count = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id,
            'name': t.name,
            'date': t.date,
            'time': t.time,
            'sport': t.sport or gnd.get('sport_types', '—'),
            'max_size': t.max_size,
            'members': member_count,
            'school_name': gnd.get('school_name', '—'),
            'address': gnd.get('address', '—'),
            'is_open': t.is_open
        })

    return render_template('teams_list.html', items=items)


@app.route('/my-teams')
def my_teams():
    """Команды, где я состою/владею."""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    t_ids = [tm.team_id for tm in TeamMember.query.filter_by(user_id=user_id).all()]
    if t_ids:
        teams = Team.query.filter(Team.id.in_(t_ids)).order_by(Team.date, Team.time).all()
    else:
        teams = []

    grounds = {g['id']: g for g in load_grounds()}
    items = []
    for t in teams:
        gnd = grounds.get(t.ground_id, {})
        members = TeamMember.query.filter_by(team_id=t.id).count()
        items.append({
            'id': t.id,
            'name': t.name,
            'date': t.date,
            'time': t.time,
            'sport': t.sport or gnd.get('sport_types', '—'),
            'max_size': t.max_size,
            'members': members,
            'school_name': gnd.get('school_name', '—'),
            'address': gnd.get('address', '—'),
            'is_open': t.is_open
        })

    return render_template('my_teams.html', items=items)


@app.route('/teams/<int:team_id>')
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

    is_owner = bool(user and user.id == t.owner_id)
    i_am_member = bool(user and TeamMember.query.filter_by(team_id=t.id, user_id=user.id).first())
    member_count = len(members)

    return render_template('team_detail.html',
                           team=t, gnd=gnd, members=mlist, member_count=member_count,
                           is_owner=is_owner, i_am_member=i_am_member)


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

    count = TeamMember.query.filter_by(team_id=team_id).count()
    if count >= t.max_size:
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

    # владелец не может уйти, пока открыт набор (может закрыть)
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
#  Админ-просмотр
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
    grounds = {g['id']: g for g in load_grounds()}

    items = []
    for b in bookings:
        u = users.get(b.user_id)
        g = grounds.get(b.ground_id, {})
        items.append({
            'id': b.id,
            'date': b.date,
            'time': b.time,
            'comment': b.comment,
            'user_id': b.user_id,
            'user_name': f"{(u.first_name or '')} {(u.last_name or '')}".strip() if u else '—',
            'username': u.username if u else '—',
            'tg_id': u.tg_id if u else '—',
            'school_name': g.get('school_name', '—'),
            'address': g.get('address', '—'),
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
            'id': b.id,
            'date': b.date,
            'time': b.time,
            'comment': b.comment,
            'school_name': g.get('school_name', '—'),
            'address': g.get('address', '—'),
            'sport_types': g.get('sport_types', '—'),
        })
    return render_template('admin_user.html', u=u, items=items)

# =======================
#  Запуск
# =======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
