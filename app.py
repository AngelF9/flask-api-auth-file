import os
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
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
app.config["SQLALCHEMY_DATABASE_URI"] = ("mysql+pymysql://new_user:testing123@localhost/user_db") #Sam's db url for testing only
#app.config["SQLALCHEMY_DATABASE_URI"] = ("mysql+pymysql://root:new_password@localhost/flask_api") #Angel's configuration
app.config["SECRET_KEY"] = "your_secret_key" #configure it to your liking

app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB
app.config["UPLOAD_EXTENSIONS"] = [".jpg", ".png", ".gif", ".txt"]
app.config["UPLOAD_PATH"] = "uploads"

os.makedirs(app.config["UPLOAD_PATH"], exist_ok=True)  # Makes a folder in project directory called 'uploads'

# initialize the SQLAlchemy object
db = SQLAlchemy(app)

# Define user model
class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  password_hash = db.Column(db.String(512), nullable=False)  # Storing hashed password 

  # add function to generate hashed password
  def set_password(self, password):
      self.password_hash = generate_password_hash(password) 
      
  # add function to check the hashed password again user input
  def check_password(self, password):
      return check_password_hash(self.password_hash, password)
    
with app.app_context():
 db.create_all()
 User.query.delete()
 db.session.commit() 
 #Create a user
 test_user = User(username='testuser')
 test_user.set_password('testpass')
 db.session.add(test_user)
 db.session.commit()



class Item(db.Model):
 id = db.Column(db.Integer, primary_key=True)
 name = db.Column(db.String(80), nullable=False)
 description = db.Column(db.String(250), nullable=False)
 is_public = db.Column(db.Boolean, default=True)


with app.app_context():
 db.create_all()
 Item.query.delete()
 db.session.commit()
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

#File size too large error
@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({"error": "File size exceeds the max limit"}), 413


# --- Task 3: Authentication ---


# Login route to generate JWT token
@app.route("/login", methods=["POST"])
def login():
    auth = request.get_json()
    print("Authorized data received: ", auth)
    user = User.query.filter_by(username=auth.get("username")).first()
    if user and user.check_password(auth.get("password")):
        token = jwt.encode({"username": auth["username"]}, app.config["SECRET_KEY"], algorithm="HS256")
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Invalid credentials!"}), 401


# protected route
@app.route("/protected", methods=["GET"])
def protected():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"message": "Token is missing!"}), 403
    
     # Split to get the token part only
    try:
        token = auth_header.split(" ")[1]  # Extracts the token part
    except IndexError:
            return jsonify({"message": "Token format is invalid!"}), 401

    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return jsonify({"message": f'Welcome, {data["username"]}!'})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
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

    # Save the file to the upload folder
    uploaded_file.save(os.path.join(app.config["UPLOAD_PATH"], filename))
    return jsonify({"message": "File successfully uploaded", "filename": filename}), 200


# --- TASK 5 ---

#public route to allow users to view a list of items

#Also part of task 6 to GET the list of items (READ operation)
@app.route("/items", methods=["GET"])
def get_public_items():
    items = Item.query.filter_by(is_public=True).all()
    items_list = [
        {"id": item.id, "name": item.name, "description": item.description}
        for item in items
    ]
    return jsonify(items_list)

# --- TASK 6 ---

# GET - Get specific item by ID (READ Operation)
@app.route("/items/<int:item_id>", methods=["GET"])
def get_item(item_id):
    item = Item.query.get_or_404(item_id)
    return jsonify({
        "id": item.id,
        "name": item.name,
        "description": item.description,
        "is_public": item.is_public
    }, 
    )

# POST - Create new item (CREATE operation)
@app.route("/items", methods=["POST"])
def create_item():
    data = request.get_json()
    
    if not data or not data.get("name") or not data.get("description"):
        return jsonify({"error": "Name and description are required"}), 400
    
    new_item = Item(
        name=data["name"],
        description=data["description"],
        is_public=data.get("is_public", True)
    )
    
    try:
        db.session.add(new_item)
        db.session.commit()
        return jsonify({
            "id": new_item.id,
            "name": new_item.name,
            "description": new_item.description,
            "is_public": new_item.is_public
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# PUT - Update existing item (UPDATE Operation)
@app.route("/items/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    item = Item.query.get_or_404(item_id)
    data = request.get_json()
    
    if "name" in data:
        item.name = data["name"]
    if "description" in data:
        item.description = data["description"]
    if "is_public" in data:
        item.is_public = data["is_public"]
    
    try:
        db.session.commit()
        return jsonify({
            "id": item.id,
            "name": item.name,
            "description": item.description,
            "is_public": item.is_public
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# DELETE - Delete item (DELETE Operation)
@app.route("/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    try:
        db.session.delete(item)
        db.session.commit()
        return jsonify({"message": "Item deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
