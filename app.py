from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
import time
import hashlib
import hmac
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'f7d2fca7d3e6fae2b43a958cbb9aa19fb291df1b8ccdb31844fc2648c9176f78'

# === База данных ===
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# === Модели ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    tg_id = db.Column(db.String(50), unique=True, nullable=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    ground_id = db.Column(db.Integer)
    date = db.Column(db.String(10))
    time = db.Column(db.String(10))

# === Регистрация ===
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phone']
        if User.query.filter_by(phone=phone).first():
            flash('Этот номер уже зарегистрирован.')
        else:
            user = User(phone=phone)
            db.session.add(user)
            db.session.commit()
            flash('Регистрация прошла успешно!')
            return redirect(url_for('main', user_id=user.id))
    return render_template('register.html')

# === Авторизация ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phone']
        user = User.query.filter_by(phone=phone).first()
        if user:
            return redirect(url_for('main', user_id=user.id))
        else:
            flash('Пользователь не найден. Сначала зарегистрируйтесь.')
            return redirect(url_for('register'))
    return render_template('login.html')

# === Главная с картой ===
@app.route('/main')
def main():
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('register'))

    df = pd.read_excel('data/grounds.xlsx')
    df = df.rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })
    df['latitude'] = pd.to_numeric(df['latitude'], errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'], errors='coerce')
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index
    grounds = df.to_dict(orient='records')

    return render_template('main.html', user=user, grounds=grounds)

# === Запись на площадку ===
@app.route('/book/<int:ground_id>', methods=['GET', 'POST'])
def book(ground_id):
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('register'))

    df = pd.read_excel('data/grounds.xlsx')
    df = df.rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index

    ground = df[df['id'] == ground_id].iloc[0].to_dict()

    today = datetime.today().strftime('%Y-%m-%d')
    time_slots = ['10:00', '12:00', '14:00', '16:00', '18:00']

    date = request.args.get('date', today)
    bookings = Booking.query.filter_by(ground_id=ground_id, date=date).all()
    booked_slots = [b.time for b in bookings]

    if request.method == 'POST':
        date = request.form['date']
        time_slot = request.form['time']
        if Booking.query.filter_by(ground_id=ground_id, date=date, time=time_slot).first():
            flash('Это время уже занято.')
        else:
            new_booking = Booking(user_id=user.id, ground_id=ground_id, date=date, time=time_slot)
            db.session.add(new_booking)
            db.session.commit()
            flash('Вы успешно записались!')
            return redirect(url_for('my_bookings', user_id=user.id))

    return render_template('book.html', ground=ground, today=today, time_slots=time_slots,
                           booked_slots=booked_slots, user=user)

# === Список записей пользователя ===
@app.route('/my_bookings')
def my_bookings():
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    bookings = Booking.query.filter_by(user_id=user_id).all()

    df = pd.read_excel('data/grounds.xlsx')
    df = df.rename(columns={
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)': 'sport_types'
    })
    df.dropna(subset=['latitude', 'longitude'], inplace=True)
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index

    for b in bookings:
        ground = df[df['id'] == b.ground_id].iloc[0].to_dict()
        b.ground = ground

    return render_template('my_bookings.html', bookings=bookings, user=user)

# === Список участников на площадке ===
@app.route('/group-check')
def group_check():
    ground_id = request.args.get('ground_id')
    date = request.args.get('date')
    time = request.args.get('time')

    bookings = Booking.query.filter_by(ground_id=ground_id, date=date, time=time).all()
    users = []
    for b in bookings:
        u = User.query.get(b.user_id)
        if u:
            users.append({'first_name': u.first_name or '', 'last_name': u.last_name or ''})
    return jsonify(users)

# === Telegram авторизация ===
@app.route('/tg_auth')
def tg_auth():
    data = request.args.to_dict()
    if not verify_telegram_auth(data):
        return "Ошибка авторизации через Telegram", 403

    tg_id = data['id']
    existing_user = User.query.filter_by(tg_id=tg_id).first()
    if existing_user:
        flash(f"Добро пожаловать, {existing_user.first_name or 'пользователь'}!")
        return redirect(url_for('main', user_id=existing_user.id))
    else:
        user = User(
            tg_id=tg_id,
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            username=data.get('username')
        )
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрированы через Telegram!')
        return redirect(url_for('main', user_id=user.id))

# === Проверка подписи Telegram ===
def verify_telegram_auth(data):
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False

    bot_token = '8066729349:AAHmcXZaWus5J94kWpnzHGaXKnXPdhmfdn8'
    secret_key = hashlib.sha256(bot_token.encode()).digest()

    check_hash = data.pop('hash', '')
    sorted_data = sorted([f"{k}={v}" for k, v in data.items()])
    data_check_string = '\n'.join(sorted_data)
    hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return hmac_hash == check_hash

# === Запуск ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
