#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        if not data:
            return {'errors': ['No data provided']}, 422
            
        # Validate required fields
        required_fields = ['username', 'password']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        
        if missing_fields:
            return {'errors': [f'Missing {field}' for field in missing_fields]}, 422

        # Check if username already exists
        existing_user = User.query.filter(User.username == data['username']).first()
        if existing_user:
            return {'errors': ['Username already exists']}, 422

        try:
            # Create new user
            user = User(
                username=data['username'],
                bio=data.get('bio'),
                image_url=data.get('image_url')
            )
            
            # Set password using the User model's password_hash setter
            user.password_hash = data['password']
            
            # Add to database
            db.session.add(user)
            db.session.commit()
            
            # Set session
            session['user_id'] = user.id
            
            # Return user data
            return user.to_dict(), 201
            
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Database integrity error']}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 422
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}, 422
        
        user = User.query.filter(User.username == username).first()
        
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        # Return recipes with user information
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [recipe.to_dict() for recipe in recipes], 200
    
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        data = request.get_json()
        if not data:
            return {'errors': ['No data provided']}, 422
            
        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )
            
            db.session.add(recipe)
            db.session.commit()
            
            return recipe.to_dict(), 201
            
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)