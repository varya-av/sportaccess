from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
import time, hashlib, hmac, pandas as pd
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

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


# === Маршруты входа ===
@app.route('/')
def index():
    # покажем кнопку логина
    return redirect(url_for('login'))

@app.route('/login')
def login():
    # Страница с Telegram Login Widget (templates/login.html)
    return render_template('login.html')


# === Главная страница с картой ===
@app.route('/main')
def main():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    # Загружаем площадки из Excel
    xlsx_path = 'data/grounds.xlsx'
    if not os.path.exists(xlsx_path):
        abort(500, f'Файл {xlsx_path} не найден')

    df = pd.read_excel(xlsx_path)

    # Переименуем колонки (оставляем только нужные)
    df = df.rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })[['latitude', 'longitude', 'school_name', 'address', 'sport_types']]

    # ВАЖНО: десятичные запятые → точки
    df['latitude'] = pd.to_numeric(df['latitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'].astype(str).str.replace(',', '.', regex=False), errors='coerce')

    # Чистим и даём ID
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index

    grounds = df.to_dict(orient='records')
    return render_template('main.html', user=user, grounds=grounds)


# === Авторизация через Telegram Login Widget ===
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


# === Выход ===
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# === Проверка подписи Telegram ===
def verify_telegram_auth(data):
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False

    # По твоей просьбе — токен остаётся в коде (небезопасно для продакшена).
    bot_token = '7971252908:AAGfTw5shz1qRmioIOh_PYNSzEDEsyEAmUI'
    secret_key = hashlib.sha256(bot_token.encode()).digest()

    check_hash = data.pop('hash', '')
    data_check_string = '\n'.join(sorted(f"{k}={v}" for k, v in data.items()))
    hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac_hash == check_hash


# === Запуск локально ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
