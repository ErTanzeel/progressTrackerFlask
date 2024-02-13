from flask import Blueprint, app, request, jsonify
from auth import generate_token, verify_token, JWT_SECRET_KEY, JWT_EXPIRATION_DELTA
import bcrypt
import jwt
from connections import users


auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/register', methods=['POST'])
def register_route():
    try:
        user_data = request.get_json()
        print("userdata",user_data)

        username = user_data.get('username')
        email = user_data.get('email')
        role = user_data.get('role')
        password = user_data.get('password')
        
        if not username or not email or not role or not password:  
            return 'All fields required', 400

        if role not in ['admin', 'user']:
            return 'Invalid role. Please provide either "admin" or "user"', 400

        existing_user = users.find_one({'username': username})

        if existing_user is None:
            hashpass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            users.insert_one({
                'username': username,
                'email': email,
                'password': hashpass,
                'role': role,  
            })

            return 'Created Successfully', 201

        return 'User Already exists', 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500


@auth_blueprint.route('/login', methods=['POST'])
def login_route():
    if request.method == 'POST':
        user_data = request.get_json()
        print('userdata',user_data)

        login_user = users.find_one({'email': user_data['email']})

        if login_user and bcrypt.checkpw(user_data['password'].encode('utf-8'), login_user['password']):
            login_user['_id'] = str(login_user['_id'])
            token = generate_token(login_user)

            response_data = {
                'status': 'success',
                'message': 'Login successful',
                'token': token,
                '_id': login_user['_id'],
                'role': login_user['role'],
                'username': login_user['username']
            }

            return jsonify(response_data), 200

        return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 400


@auth_blueprint.route('/users', methods=['GET'])
def get_all_users_route():
    try:
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token missing'}), 401

        if verify_token(token):
            jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])['username']

            users_data = list(users.aggregate([
                {
                    '$project': {
                        'username': 1,
                        '_id': {'$toString': '$_id'},
                        'email': 1,
                        'role': 1,
                        'tasks': {'$ifNull': ['$tasks', []]}
                    }
                }
            ]))

            return jsonify({'status': 'success', 'users': users_data}), 200
        else:
            return 'Invalid Token', 401

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

