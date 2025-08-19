from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import time
import hashlib
import hmac

app = Flask(__name__)
app.config['SERVER_NAME'] = 'sportaccess.onrender.com'  # 👈 добавили это
app.secret_key = 'f7d2fca7d3e6fae2b43a958cbb9aa19fb291df1b8ccdb31844fc2648c9176f78'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# === Модель пользователя ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    tg_id = db.Column(db.String(50), unique=True, nullable=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    username = db.Column(db.String(100))


# === Главная страница регистрации ===
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
            return redirect(url_for('register'))
    return render_template('register.html')


# === Авторизация через Telegram ===
@app.route('/tg_auth')
def tg_auth():
    data = request.args.to_dict()

    if not verify_telegram_auth(data):
        return "Ошибка авторизации через Telegram", 403

    tg_id = data['id']
    existing_user = User.query.filter_by(tg_id=tg_id).first()

    if existing_user:
        flash(f"Добро пожаловать обратно, {existing_user.first_name or 'пользователь'}!")
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

    return redirect(url_for('register'))


# === Проверка подписи Telegram (безопасность) ===
def verify_telegram_auth(data):
    auth_date = data.get('auth_date')
    if not auth_date or time.time() - int(auth_date) > 86400:
        return False  # слишком старые данные

    secret_key = hashlib.sha256(b'8066729349:AAHmcXZaWus5J94kWpnzHGaXKnXPdhmfdn8').digest()  # замени на токен от BotFather
    check_hash = data.pop('hash', '')

    sorted_data = sorted([f"{k}={v}" for k, v in data.items()])
    data_check_string = '\n'.join(sorted_data)

    hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return hmac_hash == check_hash


# === Запуск приложения ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)

