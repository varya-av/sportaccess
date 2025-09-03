from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, jsonify, flash, send_from_directory, g
)
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
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

# Фикс авторизации в Telegram Web (iframe): куки третьей стороны должны быть Secure + SameSite=None
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
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    grounds = load_grounds()
    ground = next((g for g in grounds if g['id'] == ground_id), None)
    if not ground:
        abort(404, 'Площадка не найдена')

    if request.method == 'POST':
        date = request.form.get('date', '').strip()
        tm = request.form.get('time', '').strip()
        comment = request.form.get('comment', '').strip()

        if not date or not tm:
            flash('Укажите дату и время.')
            return render_template('book.html', user=user, ground=ground)

        b = Booking(user_id=user.id, ground_id=ground_id, date=date, time=tm, comment=comment)
        db.session.add(b)
        db.session.commit()
        flash('Запись создана.')
        return redirect(url_for('my_bookings'))

    return render_template('book.html', user=user, ground=ground)


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
