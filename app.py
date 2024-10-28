from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    abort,
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import jwt
import os


# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

# create instance of Flask class
app = Flask(__name__)

# configure MySQL database connection
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:new_password@localhost/flask_api"
)
app.config['SECRET_KEY'] = 'your_secret_key'

# initialize the SQLAlchemy object
db = SQLAlchemy(app)


# Define user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Storing hashed password

    # add function to generate hashed password
    def set_password(self, password):
        self.password = generate_password_hash(password)

    # add function to check the hashed password again user input
    def check_password(self, password):
        return check_password_hash(self.password, password)


# --- Task 2: Error Handling ---


# handle 400  bad request
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "msg": str(error)}), 400


# handle 401  Unauthorized
@app.errorhandler(401)
def unauthorized(error):
    return (
        jsonify(
            {
                "error": "Unauthorized",
                "msg": "You are not authorized to access this resource",
            }
        ),
        401,
    )


# handle 404 Not Found
@app.errorhandler(404)
def not_found(error):
    return (
        jsonify(
            {"error": "Not Found", "msg": "The requested resource could not be found"}
        ),
        404,
    )


# handle 500 internal server error
@app.errorhandler(500)
def server_error(error):
    return (
        jsonify({"error": "Serve error", "msg": "An internal server error occurred."}),
        500,
    )


# example: testing route that does not exist (trigger 404 not found)
@app.route("/error")
def error_route():
    abort(404)


# handle 403 missing or invalid tokens error
@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden", "msg": "You do not have permission to access this resource."}), 403


# --- Task 3: Authentication ---

#Login route to generate JWT token
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
   # user = User.query.filter_by(username=auth['username']).first()
    user = {'username': 'testuser', 'password': generate_password_hash('testpass')}
    if user and check_password_hash(user.password, auth['password']):
        token = jwt.encode({'username': user.username}, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials!'}), 401

#protected route
@app.route('/protected', methods=['GET'])
def protected():
        token = request.headers.get('Authorization')
        if not token:
             return jsonify({'message': 'Token is missing!'}), 403
        
        try: 
             data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
             return jsonify({'message': f'Welcome, {data["username"]}!'})
        except jwt.ExpiredSignatureError: 
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        


if __name__ == "__main__":
    app.run(debug=True)
