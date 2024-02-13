# main.py
from flask import Flask
from flask_cors import CORS
from routes.authroutes import auth_blueprint
from routes.task_routes import task_blueprint

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'

CORS(app, origins="http://localhost:3000")


app.register_blueprint(auth_blueprint, url_prefix='/auth')
app.register_blueprint(task_blueprint, url_prefix='/task')

if __name__ == '__main__':
    app.run(host='192.168.1.83', port=5000, debug=True)
