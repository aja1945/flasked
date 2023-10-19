from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

app.config['JWT_SECRET_KEY'] = ''
jwt = JWTManager(app)

if __name__ == '__main__':
    app.run(debug=True)

    from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email

class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)

    def __init__(self, title, content, user_id):
        self.title = title
        self.content = content
        self.user_id = user_id

class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

    def __init__(self, text, post_id):
        self.text = text
        self.post_id = post_id
        
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Api(app)

class UserRegistration(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', help='This field cannot be blank', required=True)
        parser.add_argument('password', help='This field cannot be blank', required=True)
        data = parser.parse_args()

        user = User.query.filter_by(username=data['username']).first()
        if user:
            return {'message': 'User already exists'}, 400

        new_user = User(
            username=data['username'],
            password=data['password'] 
        )

        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}, 201

class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', help='This field cannot be blank', required=True)
        parser.add_argument('password', help='This field cannot be blank', required=True)
        data = parser.parse_args()

        user = User.query.filter_by(username=data['username']).first()
        if user and user.password == data['password']:
            access_token = create_access_token(identity=data['username'])
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')

class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {'message': 'This is a protected route for user: ' + current_user}

api.add_resource(UserResource, '/user/<int:user_id>')

from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity

from flask_restful import Resource

class UserProfile(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user = User.query.filter_by(username=current_user).first()
        if not user:
            return {'message': 'User not found'}, 404
        return {'id': user.id, 'username': user.username, 'email': user.email}

api.add_resource(UserProfile, '/profile')