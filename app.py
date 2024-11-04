import os

import jwt
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
)

# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# create instance of Flask class
app = Flask(__name__)

# configure MySQL database connection
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:new_password@localhost/flask_api"
)
app.config["SECRET_KEY"] = "cpsc-449"

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png", ".gif", ".txt"]
app.config["UPLOAD_PATH"] = "uploads"

os.makedirs(
    app.config["UPLOAD_PATH"], exist_ok=True
)  # Makes a folder in project directory called 'uploads'

# initialize the SQLAlchemy object
db = SQLAlchemy(app)

# with app.app_context():
#    db.create_all()


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


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    is_public = db.Column(db.Boolean, default=True)


with app.app_context():
    db.create_all()
    Item.query.delete()
    db.session.commit

    sample_items = [
        Item(name="Pierce", description="math major"),
        Item(name="Hermann", description="english major"),
        Item(name="Nikos", description="biology major"),
    ]
    db.session.add_all(sample_items)
    db.session.commit()

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
    return (
        jsonify(
            {
                "error": "Forbidden",
                "msg": "You do not have permission to access this resource.",
            }
        ),
        403,
    )


@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({"error": "File size exceeds the max limit"}), 413


# --- Task 3: Authentication ---


# Login route to generate JWT token
@app.route("/login", methods=["POST"])
def login():
    auth = request.get_json()
    print("Authorized data received: ", auth)
    # user = User.query.filter_by(username=auth['username']).first()
    # user = {'username': 'testuser', 'password': generate_password_hash('testpass')}
    # if user and check_password_hash(user.password, auth['password']):
    if (
        auth
        and auth.get("username") == "testuser"
        and auth.get("password") == "testpass"
    ):
        # token = jwt.encode({'username': user.username}, app.config['SECRET_KEY'], algorithms=['HS256'])
        token = jwt.encode(
            {"username": auth["username"]}, app.config["SECRET_KEY"], algorithm="HS256"
        )
        print("Token generated: ", token)
        return jsonify({"token": token})
    else:
        print("Invalid credentials")
        return jsonify({"message": "Invalid credentials!"}), 401


# protected route
@app.route("/protected", methods=["GET"])
def protected():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing!"}), 403

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        print("Token received in header:", token)  # Debug: Print token received
        return jsonify({"message": f'Welcome, {data["username"]}!'})
    except jwt.ExpiredSignatureError:
        print("Token expired")  # Debug
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        print("Invalid token")  # Debug
        return jsonify({"message": "Invalid token!"}), 401


# --- Task 4 File Handling ---


# file submission form
@app.route("/uploads")
def upload():
    return """
    <html>
    <body>
    <h1>Upload a file</h1>
    <form action="/sendFile" method="POST" enctype="multipart/form-data">
        <input type="file" name="file"/><br>
        <input type="submit" value="Upload"/>
    </form>
    </body>
    </html>
    """


# Upload file endpoint
@app.route("/sendFile", methods=["POST"])
def sendFile():

    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Secure and validate the filename
    filename = secure_filename(uploaded_file.filename)
    if os.path.splitext(filename)[1] not in app.config["UPLOAD_EXTENSIONS"]:
        return jsonify({"error": "Invalid file type"}), 400

    # Save the file
    uploaded_file.save(os.path.join(app.config["UPLOAD_PATH"], filename))
    return jsonify({"message": "File successfully uploaded", "filename": filename}), 200


# --- TASK 5 ---
@app.route("/items", methods=["GET"])
def get_public_items():
    items = Item.query.filter_by(is_public=True).all()
    items_list = [
        {"id": item.id, "name": item.name, "description": item.description}
        for item in items
    ]
    return jsonify(items_list)


if __name__ == "__main__":
    app.run(debug=True)
