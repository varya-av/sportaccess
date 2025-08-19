import requests
from flask import Flask
from models import db, SportsGround

YANDEX_API_KEY = "ТВОЙ_КЛЮЧ_ЗДЕСЬ"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sportgrounds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def normalize_address(addr):
    addr = str(addr)
    if not addr.lower().startswith("королёв") and "королёв" not in addr.lower():
        addr = "город Королёв, " + addr

    addr = addr.replace("г.", "").replace("ул.", "") \
               .replace("д.", "").replace("мкр.", "") \
               .replace("МО", "").replace("М.О.", "") \
               .replace("г.о.", "").replace("г,", "г") \
               .replace("д,", "д").replace("мкр,", "мкр") \
               .replace("Королев", "Королёв")  # исправим на правильный вариант
    return addr.strip()

def get_coords(address):
    url = f"https://geocode-maps.yandex.ru/1.x/?apikey={YANDEX_API_KEY}&geocode={address}&format=json"
    response = requests.get(url)
    if response.status_code == 200:
        try:
            pos = response.json()['response']['GeoObjectCollection']['featureMember'][0]['GeoObject']['Point']['pos']
            lon, lat = map(float, pos.split())
            return lat, lon
        except (IndexError, KeyError):
            return None, None
    return None, None

with app.app_context():
    grounds = SportsGround.query.all()
    for ground in grounds:
        if ground.latitude is None or ground.longitude is None:
            clean_addr = normalize_address(ground.address)
            lat, lon = get_coords(clean_addr)
            if lat and lon:
                ground.latitude = lat
                ground.longitude = lon
                print(f"[OK] {clean_addr} → {lat}, {lon}")
            else:
                print(f"[FAIL] {clean_addr}")
    db.session.commit()
    print("Геокодирование завершено.")