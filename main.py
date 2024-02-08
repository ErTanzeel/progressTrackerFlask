from flask import Flask, request, redirect, url_for,jsonify,make_response
from flask_pymongo import PyMongo
import pymongo.errors
import bcrypt
import jwt
import datetime
from bson import json_util
from flask_cors import CORS



app = Flask(__name__)
CORS(app, origins="http://localhost:3000")

app.config['MONGO_DBNAME'] = 'Tanzeel'
app.config["MONGO_URI"] = 'mongodb+srv://Tanzeel:tanzeel123@cluster0.hj1okol.mongodb.net/Cluster0?retryWrites=true&w=majority'
app.config['SECRET_KEY'] = 'tanz123'  # Set a secret key for session

mongo = PyMongo(app)



JWT_SECRET_KEY = 'pinaca123@'

# JWT expiration time (e.g., 1 day)
JWT_EXPIRATION_DELTA = datetime.timedelta(days=1)

def generate_token(login_user):
    payload = {'username': login_user['username']}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')


def verify_token(token):
    try:
        jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return True  # Token is verified
    except jwt.ExpiredSignatureError:
        return False  # Token has expired
    except jwt.InvalidTokenError:
        return False  # Invalid token
    

@app.route('/protected', methods=['POST'])
def protected_resource():
    token = request.headers.get('Authorization')
    print("token", token)

    if not token:
        return jsonify({'error': 'Token missing'}), 401

    if verify_token(token):
        # Token is verified
        username = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])['username']
        print('username',username)
        return jsonify({'message': f'Access granted to protected resource for {username}'}), 200
    else:
        # Token is either expired or invalid
        return jsonify({'error': 'Invalid token'}), 401
    


if __name__ == '__main__':
    try:
        # Attempt to connect to MongoDB
        mongo.init_app(app)
        print("MongoDB connected successfully.")
    except pymongo.errors.ServerSelectionTimeoutError:
        print("Error: MongoDB connection failed.")



@app.route('/register', methods=['POST'])
def register():
    try:
        user_data = request.get_json()
        print('userdata', user_data)
        users = mongo.db.users
        existing_user = users.find_one({'username': user_data.get('username')})

        if existing_user is None:
            hashpass = bcrypt.hashpw(user_data.get('password').encode('utf-8'), bcrypt.gensalt())

            # Set the default role to 'user'
            role = 'user'

       
            users.insert_one({
                'username': user_data.get('username'),
                'email': user_data.get('email'),
                'password': hashpass,
                'role': role,  # Set the role
            })

            return jsonify({'status': 'success', 'message': 'User registered successfully', 'user': existing_user}), 201

        return jsonify({'status': 'error', 'message': 'User already exists'}), 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        user_data = request.get_json()
        print('userdata', user_data)
        users = mongo.db.users
        login_user = users.find_one({'email': user_data['email']})

        if login_user and bcrypt.checkpw(user_data['password'].encode('utf-8'), login_user['password']):
            # Convert ObjectId to string for JSON serialization
            login_user['_id'] = str(login_user['_id'])

            # Generate JWT token
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



@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        users_collection = mongo.db.users

        # Perform aggregation to retrieve user data
        users_data = list(users_collection.aggregate([
            {
                '$project': {
                    'username': 1,
                    '_id': {'$toString': '$_id'},
                    'email': 1,
                    'role': 1,
                    'tasks': {'$ifNull': ['$tasks', []]}  # Include tasks field, default to empty list if not present
                }
            }
        ]))

        return jsonify({'status': 'success', 'users': users_data}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/addtask', methods=['POST'])
def add_task():
    try:
        # Extract task details from the request
        task_data = request.get_json()
        print('task_data', task_data)

        # Get the username from the task data
        username = task_data.get('user')

        # Query the user by username
        user = mongo.db.users.find_one({'username': username})

        if user:
            # Update the user document to add the new task directly
            mongo.db.users.update_one({'_id': user['_id']}, {'$push': {'tasks': task_data}})

            return jsonify({'status': 'success', 'message': 'Task added successfully'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}, 404)

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500



@app.route('/submit_task', methods=['POST'])
def submit_task():
    try:
        # Extract task details from the request
        task_data = request.get_json()
        print('task_data', task_data)

        username = task_data.get('userName')
        print('userName', username)

        user = mongo.db.users.find_one({'username': username})

        if user:
            # Find the task by title in the user's tasks
            task_title = task_data.get('userTaskTitle')
            print('title', task_title)
            task_index = next((index for (index, task) in enumerate(user['tasks']) if task['title'] == task_title), None)

            if task_index is not None:
                mongo.db.users.update_one({'_id': user['_id'], 'tasks.title': task_title},
                           {'$set': {
                               'tasks.$.completed': True,
                               'tasks.$.textarea_field': task_data.get('editTask'),
                               'tasks.$.percentage_field': task_data.get('progress')}})


                return jsonify({'status': 'success', 'message': 'Task submitted successfully'}), 200
            else:
                return jsonify({'status': 'error', 'message': 'Task not found for the user'}), 404
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500




if __name__ == '__main__':
    app.run( port=5000, debug=True)


