from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
)

# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

# create instance of Flask class
app = Flask(__name__)

# configure MySQL database connection
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mysql+pymysql://root:new_password@localhost/flask_api"
)

# initialize the SQLAlchemy object
db = SQLAlchemy(app)


# Define user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Storing hashed password

    # add function to generate hashed password

    # add function to check the hashed password again user input


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


if __name__ == "__main__":
    app.run(debug=True)
