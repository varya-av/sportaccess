from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
import time, hashlib, hmac
import os
from datetime import datetime
from io import BytesIO
import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# === Модели ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True)
    tg_id = db.Column(db.String(50), unique=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ground_id = db.Column(db.Integer)
    date = db.Column(db.String(20))
    time = db.Column(db.String(10))
    qr_code_path = db.Column(db.String(200))

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
            flash('Пользователь не найден')
            return redirect(url_for('register'))
    return render_template('login.html')

# === Главная карта ===
@app.route('/main')
def main():
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('register'))

    df = pd.read_excel('data/grounds.xlsx')
    df = df.rename(columns={
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Для какого вида спорта предназначена': 'sport_types'
    })
    df = df.dropna(subset=['latitude', 'longitude'])
    df = df.reset_index()
    df.rename(columns={'index': 'id'}, inplace=True)

    grounds = df.to_dict(orient='records')
    return render_template('main.html', user=user, grounds=grounds)

# === Страница записи ===
@app.route('/book/<int:ground_id>', methods=['GET', 'POST'])
def book(ground_id):
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('register'))

    df = pd.read_excel('data/grounds.xlsx')
    df = df.dropna(subset=['latitude', 'longitude']).reset_index()
    df.rename(columns={
        'index': 'id',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address',
        'Широта (lat)': 'latitude',
        'Долгота (lon)': 'longitude',
        'Для какого вида спорта предназначена': 'sport_types'
    }, inplace=True)

    ground = df[df['id'] == ground_id].iloc[0].to_dict()
    today = datetime.now().strftime('%Y-%m-%d')
    time_slots = ['10:00', '12:00', '14:00', '16:00', '18:00']

    if request.method == 'POST':
        date = request.form['date']
        time_ = request.form['time']
        existing = Booking.query.filter_by(ground_id=ground_id, date=date, time=time_).first()
        if existing:
            flash("Этот слот уже занят!")
        else:
            qr_text = f"{user.first_name} {user.last_name} записан на {ground['school_name']} {date} в {time_}"
            qr = qrcode.make(qr_text)
            qr_path = f"static/qr/booking_{user.id}_{ground_id}_{date}_{time_.replace(':', '')}.png"
            qr.save(qr_path)

            pdf_path = f"static/pdf/booking_{user.id}_{ground_id}_{date}_{time_.replace(':', '')}.pdf"
            c = canvas.Canvas(pdf_path, pagesize=A4)
            c.setFont("Helvetica", 14)
            c.drawString(100, 800, "Подтверждение записи")
            c.drawString(100, 780, f"ФИО: {user.first_name} {user.last_name}")
            c.drawString(100, 760, f"Площадка: {ground['school_name']}")
            c.drawString(100, 740, f"Дата и время: {date} {time_}")
            c.drawImage(qr_path, 100, 600, width=150, height=150)
            c.save()

            booking = Booking(user_id=user.id, ground_id=ground_id, date=date, time=time_, qr_code_path=qr_path)
            db.session.add(booking)
            db.session.commit()

            flash("Вы успешно записались!")
            return redirect(url_for('my_bookings', user_id=user.id))

    booked_slots = [b.time for b in Booking.query.filter_by(ground_id=ground_id, date=request.args.get('date')).all()]
    return render_template('book.html', ground=ground, time_slots=time_slots, booked_slots=booked_slots, today=today)

# === Список записей пользователя ===
@app.route('/my-bookings')
def my_bookings():
    user_id = request.args.get('user_id')
    user = User.query.get(user_id)
    bookings = Booking.query.filter_by(user_id=user_id).all()

    df = pd.read_excel('data/grounds.xlsx')
    df = df.dropna(subset=['latitude', 'longitude']).reset_index()
    df.rename(columns={
        'index': 'id',
        'Название учреждения(краткое)': 'school_name',
        'Адрес объекта': 'address'
    }, inplace=True)

    id_to_ground = {row['id']: row for _, row in df.iterrows()}
    for b in bookings:
        b.ground = id_to_ground.get(b.ground_id, {})

    return render_template('my_bookings.html', user=user, bookings=bookings)

# === Отмена записи ===
@app.route('/cancel-booking/<int:booking_id>')
def cancel_booking(booking_id):
    booking = Booking.query.get(booking_id)
    if booking:
        db.session.delete(booking)
        db.session.commit()
        flash('Запись отменена.')
    return redirect(url_for('my_bookings', user_id=booking.user_id))

# === Проверка участников ===
@app.route('/group-check')
def group_check():
    ground_id = request.args.get('ground_id')
    date = request.args.get('date')
    time_ = request.args.get('time')
    bookings = Booking.query.filter_by(ground_id=ground_id, date=date, time=time_).all()
    users = [User.query.get(b.user_id) for b in bookings]
    return jsonify([{'first_name': u.first_name, 'last_name': u.last_name} for u in users if u])

# === Запуск ===
if __name__ == '__main__':
    os.makedirs('static/qr', exist_ok=True)
    os.makedirs('static/pdf', exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
