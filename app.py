from flask import Flask, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from passlib.hash import pbkdf2_sha256

from db import db
import secrets

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = str(secrets.SystemRandom().getrandbits(128))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    favorite_quote = db.Column(db.String(80), nullable=False)

jwt = JWTManager(app)

db.init_app(app)

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = pbkdf2_sha256.hash(request.json['password'])
    favorite_quote = request.json['favorite_quote']

    if not username or not password or not favorite_quote:
        return {"message": "Missing username, password, or favorite_quote"}, 400
    
    # check if user already exists
    if User.query.filter_by(username=username).first():
        return {"message": "User already exists"}, 409
    
    user = User(username=username, password=password, favorite_quote=favorite_quote)
    
    db.session.add(user)
    db.session.commit()

    return {"message": "User created"}, 201

# add method to check all users in the database
@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return {"users": [{"username": user.username, "password": user.password, "favorite_quote": user.favorite_quote} for user in users]}

# check if user exists and password is correct, then generate and return an access_token
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    user = User.query.filter_by(username=username).first()

    if user and pbkdf2_sha256.verify(password, user.password):
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token}, 200

    return {"message": "Invalid credentials"}, 401

# protect the route with jwt_required
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if not user:
        return {"message": "User not found"}, 404

    return {"username": user.username, "favorite_quote": user.favorite_quote}


with app.app_context():
    db.create_all()
    debug = True






