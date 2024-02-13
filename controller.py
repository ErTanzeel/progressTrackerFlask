from flask import Flask, request, jsonify
from flask_cors import CORS
from auth import JWT_SECRET_KEY, generate_token, verify_token
from connections import initialize_mongo
from bson import ObjectId, json_util
import bcrypt
import jwt
import datetime
import random
import string
import json


app = Flask(__name__)
CORS(app, origins="http://localhost:3000")

users, taskcollections = initialize_mongo(app)


def register():
    try:
        user_data = request.get_json()

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



def login():
    if request.method == 'POST':
        user_data = request.get_json()

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



def get_all_users():
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



def add_task():
    try:
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token missing'}), 401

        if verify_token(token):
            loginusername = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])['username']
            
            user = users.find_one({'username': loginusername})
            
            if user and user.get('role') == 'admin':
                task_data = request.get_json()
                
                title = task_data.get('title')
                username = task_data.get('username')
                
                if not all((username, title)):
                    return 'All fields required', 400
                
                user = users.find_one({'username': username})
                
                if user:
                    task_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    time_a = datetime.datetime.now().strftime("%Y-%m-%d")
                    taskcollections.insert_one({
                        "title": title,
                        "task_id": task_id,
                        "date": time_a,
                        "user_id": ObjectId(user['_id']),
                        "percentage":0,
                        'username':username
                    })

                    return 'Task added Successfully', 200
                else:
                    return 'user not found',404
            else:
                return 'Only admin can perform this action', 403
        else:
            return 'Invalid Token', 401

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500


def get_tasks():
    try:
        param_value = request.args.get('id')
        print('param_value:', param_value)  # Print for debugging purposes

        param_value = param_value.strip()  # Remove leading and trailing whitespaces

        try:
            param_obj_id = ObjectId(param_value)
        except Exception as ex:
            return jsonify({'status': 'error', 'message': f'Invalid user ID parameter: {str(ex)}'}), 400

        # Find all tasks with the given user ID in the MongoDB collection
        tasks = list(taskcollections.find({'user_id': param_obj_id}))

        if not tasks:
            return jsonify({'status': 'error', 'message': 'No tasks found for the given user ID'}), 404

        # Convert ObjectId to string representation for serialization
        serialized_tasks = json.dumps(tasks, default=str)

        # Send the tasks data as JSON
        return jsonify(json.loads(serialized_tasks))
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500
    
def get_all_tasks():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return 'Token is Missing', 401
        
        if not verify_token(token):
            return 'Invalid Token', 401
        

        all_tasks_cursor = taskcollections.find({}, {'_id': 0, 'user_id': 0})

        all_tasks = list(all_tasks_cursor)

        return jsonify({'status': 'success', 'tasks': all_tasks}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500


def submit_task():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return 'Token is Missing', 401

        if not verify_token(token):
            return 'Invalid Token', 401

        task_data = request.get_json()

        textarea = task_data.get('textarea')
        user_id = task_data.get('user_id')
        task_id = task_data.get('task_id')
        percentage = task_data.get('percentage') 

        task = taskcollections.find_one({'user_id': ObjectId(user_id), 'task_id': task_id})

        if task:
            completed = percentage == 100
            taskcollections.update_one({'user_id': ObjectId(user_id), 'task_id': task_id},
                                        {'$set': {
                                            'completed': completed,
                                            'textarea_field': textarea,
                                            'percentage': percentage}})
        else:
            return  'User ID or Task ID not found', 404

        return 'Task submitted successfully', 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)
