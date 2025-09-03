from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
import time, hashlib, hmac, pandas as pd
import os, json
from urllib.parse import parse_qsl

# === Токен бота. Можно положить в переменную окружения BOT_TOKEN, но оставляю хардкод как просил ===
BOT_TOKEN = os.getenv("BOT_TOKEN", "7971252908:AAGfTw5shz1qRmioIOh_PYNSzEDEsyEAmUI")

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Куки сессии — безопасные настройки под HTTPS (Railway)
app.config.update(
    SESSION_COOKIE_SECURE=True,   # только по HTTPS
    SESSION_COOKIE_SAMESITE="Lax" # достаточный режим для WebView Telegram
)

# === База данных ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# === Модель пользователя (только Telegram) ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tg_id = db.Column(db.String(50), unique=True, nullable=True)   # Telegram ID
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))


# ======= Маршруты =======

@app.route('/health')
def health():
    return 'ok', 200


@app.route('/')
def index():
    # Для Mini App всегда ведём на /webapp
    return redirect(url_for('webapp_entry'))


# План Б — вход через Login Widget (для обычных браузеров)
@app.route('/login')
def login():
    return render_template('login.html')


# Стартовая страница Mini App (эту ссылку ставим в меню бота)
@app.route('/webapp')
def webapp_entry():
    return render_template('webapp.html')  # внутри Telegram WebApp возьмёт initData и авторизует


# Приём и проверка initData из Telegram WebApp (POST из JS)
@app.route('/tg_webapp_auth', methods=['POST'])
def tg_webapp_auth():
    init_data = request.form.get('init_data', '')
    if not init_data:
        return "no init_data", 400

    if not verify_webapp_init_data(init_data):
        return "forbidden", 403

    # Парсим initData → достаём user
    data_pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    user_json = data_pairs.get('user')
    if not user_json:
        return "no user in init_data", 400

    user_obj = json.loads(user_json)
    tg_id = str(user_obj.get('id'))

    user = User.query.filter_by(tg_id=tg_id).first()
    if not user:
        user = User(
            tg_id=tg_id,
            first_name=user_obj.get('first_name'),
            last_name=user_obj.get('last_name'),
            username=user_obj.get('username')
        )
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    # фронт после 200 перейдёт на /main
    return jsonify(status="ok")


# Login Widget (браузер): GET /tg_auth?id=...&first_name=...&hash=...
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


# Главная страница с картой
@app.route('/main')
def main():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    xlsx_path = 'data/grounds.xlsx'
    if not os.path.exists(xlsx_path):
        abort(500, f'Файл {xlsx_path} не найден на сервере')

    # Читаем Excel и оставляем нужные поля
    df = pd.read_excel(xlsx_path).rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })[['latitude', 'longitude', 'school_name', 'address', 'sport_types']]

    # Запятые → точки (иначе будут NaN)
    df['latitude']  = pd.to_numeric(df['latitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')

    # Чистим, даём ID
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index

    grounds = df.to_dict(orient='records')
    return render_template('main.html', user=user, grounds=grounds)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ======= Проверки подписи =======

# 1) Login Widget проверяется как раньше (секрет = sha256(bot_token))
def verify_telegram_auth(data: dict) -> bool:
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False

    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    check_hash = data.pop('hash', '')
    data_check_string = '\n'.join(sorted(f"{k}={v}" for k, v in data.items()))
    calc_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc_hash, check_hash)


# 2) WebApp initData: секрет = HMAC_SHA256(key="WebAppData", msg=bot_token)
def verify_webapp_init_data(init_data: str) -> bool:
    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    hash_from_tg = pairs.pop('hash', None)
    if not hash_from_tg:
        return False

    # ключ от токена
    secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()

    # k=v\nk=v... по отсортированным ключам
    data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(pairs.items(), key=lambda x: x[0]))

    # сверяем подпись
    calc_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc_hash, hash_from_tg)


# === Запуск локально ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
