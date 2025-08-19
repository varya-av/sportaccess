import os
import pandas as pd
from models import db, SportsGround, User, Booking  # Добавь нужные модели
from app import app

def init_db():
    db_path = 'sportgrounds.db'

    # 🔥 Удаляем старую базу, если существует
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"❌ Удалена старая база данных: {db_path}")

    with app.app_context():
        # 🧱 Пересоздаём таблицы
        db.create_all()
        print("✅ Таблицы пересозданы!")

        # 📦 Загружаем данные из Excel
        df = pd.read_excel("data/grounds.xlsx")  # путь к твоему Excel-файлу
        for _, row in df.iterrows():
            ground = SportsGround(
                school_name=row["Название учреждения(краткое)"],
                address=row["Адрес объекта"],
                latitude=row["Широта (lat)"],
                longitude=row["Долгота (lon)"],
                sport_types=row["Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)"]
            )
            db.session.add(ground)

        db.session.commit()
        print("✅ Данные успешно добавлены в SportsGround.")

if __name__ == "__main__":
    init_db()
