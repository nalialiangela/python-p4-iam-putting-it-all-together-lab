#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        try:
            user = User(username=username, password_hash=generate_password_hash(password), image_url=image_url, bio=bio)
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422
        except Exception as e:
            return {'error': str(e)}, 422
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
            else:
                return {'error': 'User not found'}, 404
        else:
            return {'error': 'Unauthorized'}, 401



class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = db.session.query(User).filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')

        if user_id:
            session.pop('user_id', None)
            return '', 204
        else:
            return {'error': 'Unauthorized'}, 401


class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = [{
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': user_to_dict(User.query.filter_by(id=recipe.user_id).first())
            } for recipe in Recipe.query.all()]
            return recipes, 200
        else:
            return {'message': 'Must be logged in to view'}, 401

    def post(self):
        if session.get('user_id'):
            json = request.get_json()
            recipe = Recipe()
            try:
                recipe.title = json.get('title')
                recipe.instructions = json.get('instructions')
                recipe.minutes_to_complete = json.get('minutes_to_complete')
                recipe.user_id = session['user_id']
                db.session.add(recipe)
                db.session.commit()
                recipe_json = {
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': user_to_dict(User.query.filter_by(id=recipe.user_id).first())
                }
                return recipe_json, 201
            except IntegrityError:
                db.session.rollback()
                return {'message': 'Recipe could not be created: integrity error'}, 422
            except Exception as e:
                db.session.rollback()
                return {'message': f'Recipe could not be created: {str(e)}'}, 422
        else:
            return {'message': 'Must be logged in to create a recipe'}, 401

def user_to_dict(user):
    return {
        'id': user.id,
        'username': user.username,
        'image_url': user.image_url,
        'bio': user.bio
    }


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)