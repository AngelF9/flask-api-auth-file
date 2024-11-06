# flask-api-auth-file

Class Section: CPSC 449-03
Professor: Jainish Shah
Due Date: 11/5/2024
Members: Samuel Vo, Angel Fuentes, Jacob Corletto


Instructions how to run the program:
--------------------------------------

Prerequisites
Python 3.7+ - Download from Python's official website.
MySQL Server - Download from MySQL's official website.
MySQL Workbench - Download from MySQL's officail website.
pip - Should come installed with Python; if not, install it using:

python -m ensurepip --upgrade

run pip --version to check if it is the latest one. 

Steps to Set Up
1. Clone the Repository
git clone https://github.com/AngelF9/flask-api-auth-file.git

cd  to your repo

2. Create and Activate a Virtual Environment
It’s recommended to run this project in a virtual environment to manage dependencies.

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate

3. Install Dependencies
Install the project dependencies specified in the requirements.txt file.

pip install -r requirements.txt

4. MySQL Setup and Configuration
Open MySQL and log in as root for Terminal:

mysql -u root -p

Or go to MySQL Workbench and login to local instance using root password

Create a new database and a user for this project:
Run these commands on a SQL query:

CREATE DATABASE user_db;
CREATE USER 'new_user'@'localhost' IDENTIFIED BY 'new_password';
GRANT ALL PRIVILEGES ON user_db.* TO 'new_user'@'localhost';
FLUSH PRIVILEGES;

Update Configurations in Flask

Make sure the app.config["SQLALCHEMY_DATABASE_URI"] line in the code matches your MySQL configuration:

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://new_user:new_password@localhost/user_db"

5. Our password_hash column is set to 512 characters, so you must update this in MySQL Workbench by running this command: 
ALTER TABLE user MODIFY password_hash VARCHAR(512);

To check if the size is 512 characters for the password_hash column run:

SHOW databases;
USE user_db; //Use your database name you created 'user_db' is just an example
DESCRIBE user;

It should show VARCHAR(512) next to password_hash

# Set environment variable
app.config['SECRET_KEY']='your_secret_key'  # Replace 'your_secret_key' with your preferred secret key

7. Running the Application
Run the Flask app with debugging mode enabled for development with the following command:

flask run

The API should be available at http://127.0.0.1:5000.

Ctrl + click the link to view it in the browser.

POSTMAN environment setup:
Now to test each operation out, open POSTMAN and create a new collection
Create names for each endpoint like Authentication, CRUD operations, and File Handling

Now we create HTTP requests 

For Authentication create two requests
One for Login and one for protected
POST is used for Login and GET is used for protected

For CRUD operations create 5 requests 
One for GET, GET by id, POST, DELETE, and PUT

For file handling create one for uploads
Make this a GET request

Now we use the link provided in Flask http://127.0.0.1:5000 and go through each endpoint
Authentication - http://127.0.0.1:5000/login and http://127.0.0.1:5000/protected
CRUD -  for GET, POST use http://127.0.0.1:5000/items and the rest with http://127.0.0.1:5000/items/item_id 
 Note: (substitute item_id with actual id number)

 Now to test it in Authentication login route we have to go to the "Body Tab" and set it to raw and JSON
 enter this credential which is in the database:
 {
    "username" : "testuser",
    "password" : "testpass"
 }

It should return a token
Go to the protected route and set it to the "Authorization tab" and select Bear token for Auth type 
and it should automatically generate the token from login route or you can copy and paste from login if it isn't showing up
It should send a message that you have successfully logged in

For the CRUD operations it should be fairly simple. 
Just use the Body tab, select raw, and JSON and add in information for name and description in the JSON format
Do these for the operations like POST and PUT
Return to the GET endpoint to see the updated list of items 

DELETE, PUT, and GET by id are done by adding the /id after /items/id in the link to do the operation for that specific id
Go back to the GET items endpoint to see the updated list

GET is simple without the id needed
http://127.0.0.1:5000/items and click SEND
It will return the list of items that are public

Lastly, to test out File Handling we just need to go to this link:
http://127.0.0.1:5000/sendFile

Set it to the "Body" tab and the key should be file, set it to file in the dropdown as well
Next go to Value and press it to upload a local file from your computer

Click Send to see if your file meets the requirements and if so, it should return a Uploaded Successfully message





