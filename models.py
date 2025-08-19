from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    vk_id = db.Column(db.String(50), unique=True, nullable=True)
    selected_sport = db.Column(db.String(100), nullable=True)

    # связь с бронированиями
    bookings = db.relationship('Booking', backref='user', lazy=True)

class SportsGround(db.Model):
    __tablename__ = 'sports_grounds'

    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(200))
    address = db.Column(db.String(300))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    sport_types = db.Column(db.String(200))

    # связь с бронированиями
    bookings = db.relationship('Booking', backref='ground', lazy=True)

class Booking(db.Model):
    __tablename__ = 'bookings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ground_id = db.Column(db.Integer, db.ForeignKey('sports_grounds.id'), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time_slot = db.Column(db.String(50), nullable=False)

    # здесь никаких relationship — они создаются через backref
