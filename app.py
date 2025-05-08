from flask import Flask, jsonify, request
from flask_jwt_extended import create_access_token,get_jwt_identity, JWTManager, jwt_required
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api

from modules.password_hashing import hash_password, check_password 

app = Flask(__name__)

app.config['SECRET_KEY'] = ' SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)



with app.app_context():
    db.create_all()



class UserRegistration(Resource):
    '''UserRegistration class allows the user to register in by providing their username and password.'''
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        if not username or not password:
            return {'message':'Fill all the fields'}, 400
        
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already exists'}, 400
        
        hashed_password = hash_password(password)

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {"message": "User registered successfully"}, 201

        


class UserLogin(Resource):
    '''UserLogin class allows the user to log in by providing their username and password.'''
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        
        if not username or not password:
            return {'message': 'Fill all the fields'}, 400
        
        # Query the user from the database
        user = User.query.filter_by(username=username).first()

        if not user:
            return {"error": "User not found"}, 404

        # Get the stored hashed password
        stored_hash = user.password

        # Verify password by comparing the entered password with the hashed password
        if check_password(stored_hash, password):
            access_token = create_access_token(identity=user.username)
            return {"message": "Login successful", 'access_token':access_token}, 200
        else:
            return {"error": "Invalid password"}, 400
        


class Dashboard(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'msg' : f'Hello user : {current_user}, you are in protected route i.e. in Dashboard'}, 200




# add_resource is used to add the resource to the api
# The first argument is the resource class, and the second argument is the URL endpoint
# The URL endpoint is the path that the resource will be available at
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(Dashboard, '/dashboard')


        


if __name__ == "__main__":
    app.run(debug=True)

