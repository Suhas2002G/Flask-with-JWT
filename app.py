from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_required, get_jwt
)
from flask_jwt_extended import decode_token
from redis import Redis
import datetime
from datetime import timedelta
from modules.password_hashing import Authentication



# --- App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']



# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
auth = Authentication()



# --- Redis Setup ---
redis_blocklist = Redis(host='localhost', port=6379, decode_responses=True)



# --- Token Blocklist using Redis ---
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    '''token_in_blocklist_loader: A decorator that registers a callback function to check if a token is in the blacklist.
    The function check_if_token_revoked checks whether the token's jti (JWT ID) exists in the Redis blocklist. 
    If it does, the token is revoked.'''

    jti = jwt_payload['jti']
    return redis_blocklist.get(jti) is not None


def revoke_token(jti, expires):
    # Set the token's jti in Redis until it expires
    now = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC time
    exp = datetime.datetime.fromtimestamp(expires, tz=datetime.timezone.utc)  # Ensure 'exp' is timezone-aware
    ttl = (exp - now).total_seconds()  # Calculate TTL
    redis_blocklist.setex(jti, int(ttl), "revoked")  # Store the token in Redis with TTL


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    '''refresh_token: A route to refresh an expired access token.
    The @jwt_required(refresh=True) decorator ensures the user provides a valid refresh token.
    Generates a new access token for the user and returns it.'''

    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({'access_token': access_token}), 200



# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()




# --- Routes ---
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = auth.hash_password(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201



@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'All fields are required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not auth.check_password(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify({
        'message': 'Login successful',
        'tokens': {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
    }), 200


@app.route('/logout', methods=['POST'])
@jwt_required(optional=True)
def logout():
    # 1. Revoke Access Token (if present in Authorization header)
    jwt_data = get_jwt()
    if jwt_data:
        access_jti = jwt_data["jti"]
        access_exp = jwt_data["exp"]
        revoke_token(access_jti, access_exp)

    # 2. Revoke Refresh Token (if provided)
    refresh_token = request.json.get('refresh_token') or request.headers.get('X-Refresh-Token')
    if refresh_token:
        try:
            decoded = decode_token(refresh_token)   # this returns a dictionary
            refresh_jti = decoded["jti"]
            refresh_exp = decoded["exp"]
            revoke_token(refresh_jti, refresh_exp)
        except Exception as e:
            return jsonify({"message": "Invalid refresh token"}), 400

    return jsonify({"message": "Access and Refresh tokens revoked"}), 200



@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify({'message': f'Welcome {current_user}, you are in the protected dashboard'}), 200























# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True, port=8000)
