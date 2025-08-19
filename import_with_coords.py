import pandas as pd
from flask import Flask
from models import db, SportsGround

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sportgrounds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

df = pd.read_excel("data/grounds.xlsx")

with app.app_context():
    db.drop_all()
    db.create_all()

    for _, row in df.iterrows():
        ground = SportsGround(
            school_name=row["Название учреждения(краткое)"],
            address=row["Адрес объекта"],
            ground_type=row.get("Наличие спортивной площадки на территории(хоккейная коробка, баскетбольная площадка, футбольное поле, по каждой площадке заполняется отдельно)", "не указано"),
            condition=row.get("Состояние спортивной площадки(покрытие, оборудование) - описать проблему в случае ее наличия", ""),
            sport_types=row.get("Для какого вида спорта предназначена (например футбол/баскетбол, футбольное поле, воркаут и тд.)", ""),
            is_open_access=str(row.get("Площадка работает в рамках проекта Открытый стадион? (да/нет)", "")).strip().lower() == "да",
            entry_type=row.get("Доступ на спортивную площадку осуществляется через отдельный огороженный вход(как открытый стадион) или через территорию школы", ""),
            surveillance=row.get("Наличие системы видеонаблюдения за площадкой (Варианты ответа: Безопасный регион, школьная система видеонаблюдения, отсутствует)", ""),
            dimensions=row.get("Размер площадки(заполнять для площадок в виде коробки)", ""),
            latitude=row["Широта (lat)"],
            longitude=row["Долгота (lon)"]
        )
        db.session.add(ground)

    db.session.commit()
    print("✅ Данные с координатами успешно загружены.")