from flask import Flask
from models import db, SportsGround
import pandas as pd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sportgrounds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Загружаем Excel-файл
df = pd.read_excel('data/grounds.xlsx')

with app.app_context():
    db.drop_all()
    db.create_all()

    for _, row in df.iterrows():
        ground = SportsGround(
            school_name=row.iloc[0],
            address=row.iloc[1],
            ground_type=row.iloc[2],
            condition=row.iloc[3],
            sport_types=row.iloc[4],
            is_open_access=str(row.iloc[5]).strip().lower() == "да",
            entry_type=row.iloc[6],
            surveillance=row.iloc[7],
            dimensions=row.iloc[8] if not pd.isna(row.iloc[8]) else ""
        )
        db.session.add(ground)

    db.session.commit()
    print("Данные успешно импортированы в базу.")
