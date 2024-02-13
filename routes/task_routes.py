import os
from flask import Blueprint, app, current_app, g, request, jsonify
from auth import JWT_SECRET_KEY, verify_token
from connections import taskcollections
from bson import ObjectId
import jwt  # Add import for jwt
import datetime
import random
import string
import json
from connections import users
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = None  # To be set dynamically within the request context
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


task_blueprint = Blueprint('task', __name__)
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def set_upload_folder():
    g.upload_folder = current_app.config['UPLOAD_FOLDER']


def set_upload_folder():
    g.upload_folder = current_app.config['UPLOAD_FOLDER']

task_blueprint.before_request(set_upload_folder)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@task_blueprint.route('/addtask', methods=['POST'])
def add_task_route():
    try:
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token missing'}), 401

        if verify_token(token):
            loginusername = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])['username']

            user = users.find_one({'username': loginusername})

            if user and user.get('role') == 'admin':
                task_data = request.form.to_dict()
                uploaded_file = request.files.get('image')
                print('uploadfile',uploaded_file)

                title = task_data.get('title')
                username = task_data.get('username')

                if not all((username, title, uploaded_file)) or not allowed_file(uploaded_file.filename):
                    return 'Invalid data or file type', 400

                # Save the file to a folder
                filename = secure_filename(uploaded_file.filename)
                file_path = os.path.join(g.upload_folder, filename)
                uploaded_file.save(file_path)

                task_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                time_a = datetime.datetime.now().strftime("%Y-%m-%d")

                taskcollections.insert_one({
                    "title": title,
                    "task_id": task_id,
                    "date": time_a,
                    "user_id": ObjectId(user['_id']),
                    "percentage": 0,
                    'username': username,
                    'file_path': file_path  # Add file_path to the task details
                })

                return 'Task added Successfully', 200
            else:
                return 'Only admin can perform this action', 403
        else:
            return 'Invalid Token', 401

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500

@task_blueprint.route('/gettask', methods=['GET'])
def get_tasks_route():
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




@task_blueprint.route('/getalltasks', methods=['GET'])
def get_all_tasks_route():
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



@task_blueprint.route('/submit_task', methods=['POST'])
def submit_task_route():
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
            return 'User ID or Task ID not found', 404

        return 'Task submitted successfully', 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500


