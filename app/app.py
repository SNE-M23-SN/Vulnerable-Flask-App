from flask import session, Flask, jsonify, request, Response, render_template, render_template_string, url_for
from flask_sqlalchemy import SQLAlchemy
import shutil
import tempfile
import time
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError
import json
import hashlib
import logging
import datetime
import os
from faker import Faker
import random
from werkzeug.utils import secure_filename
from docx import Document
import yaml
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
import os
import base64
import logging
from pythonjsonlogger import jsonlogger

app_port = os.environ.get('APP_PORT', 5050)

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = 'secret'
app.config['SECRET_KEY_HMAC_2'] = 'am0r3C0mpl3xK3y'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'
app.config['STATIC_FOLDER'] = None
app.debug = True
db = SQLAlchemy(app)

# Configuration for logging
logHandler = logging.StreamHandler()
fileHandler = logging.FileHandler('app.log')
formatter = jsonlogger.JsonFormatter()

logHandler.setFormatter(formatter)
fileHandler.setFormatter(formatter)
app.logger.addHandler(logHandler)
app.logger.addHandler(fileHandler)
app.logger.setLevel(logging.DEBUG)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80), unique=True)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return "<User {0}>".format(self.username)


class Customer(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    email = db.Column(db.String(80))
    ccn = db.Column(db.String(80), nullable = True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(150))


    def __repr__(self):
        return "<User {0} {1}>".format(self.first_name, self.last_name)

@app.before_first_request
def setup_users():
    app.logger.info("Setting up initial users and customers")
    db.create_all()

    if not User.query.first():
        user = User()
        user.username = 'admin'
        user.password = 'admin123'
        db.session.add(user)
        db.session.commit()
	app.logger.info("Admin user created")

    if not Customer.query.first():
        for i in range(0,5):
            fake = Faker()
            cust = Customer()
            cust.first_name = fake.first_name()
            cust.last_name = fake.last_name()
            cust.email = fake.simple_profile(sex = None)['mail']
            cust.username = fake.simple_profile(sex = None)['username']
            cust.password = str(base64.b64encode(os.urandom(16)))
            cust.ccn = fake.credit_card_number(card_type=None)
            db.session.add(cust)
            db.session.commit()
	    app.logger.info("Customer %s created", cust.username)

def get_exp_date():
    exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes = 240)
    return exp_date

def verify_jwt(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY_HMAC'], issuer='we45', leeway=10, algorithms=['HS256'])
        print("JWT Token from API: {0}".format(decoded))
        return True
    except DecodeError:
        print("Error in decoding token")
        return False
    except MissingRequiredClaimError as e:
        print('Claim required is missing: {0}'.format(e))
        return False
    except InvalidTokenError as e:
        print('Invalid token: {0}'.format(e))
        return False

def insecure_verify(token):
    decoded = jwt.decode(token, verify = False)
    print(decoded)
    return True

@app.errorhandler(404)
def pnf(e):
    app.logger.warning("404 error: %s", request.url)
    template = '''<html>
    <head>
    <title>Error</title>
    </head>
    <body>
    <h1>Oops that page doesn't exist!!</h1>
    <h3>%s</h3>
    </body>
    </html>
    ''' % request.url

    return render_template_string(template, dir = dir, help = help, locals = locals),404

def has_no_empty_params(rule):
    default = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(default) >= len(arguments)

@app.route('/', methods = ['GET'])
def sitemap():
    links = []
    for rule in app.url_map.iter_rules():
        print(rule)
	app.logger.info("Processing rule: %s",rule)
        if ("GET" in rule.methods or "POST" in rule.methods) and has_no_empty_params(rule):
            if not 'static' in rule.endpoint:
                url = url_for(rule.endpoint, **(rule.defaults or {}))
                links.append((url, rule.endpoint, ','.join(rule.methods)))

    return render_template('index.html', urls = links)


@app.route('/register/user', methods = ['POST'])
def reg_customer():
    try:
	app.logger.debug("Received request to register a new user")
        content = request.json
        if content:
            username = content['username']
            password = content['password']
	    app.logger.debug("Received username: %s", username)
            hash_pass = hashlib.md5(password).hexdigest()
	    app.logger.debug("Hashed password: %s", hash_pass)
            new_user = User(username, hash_pass)
            db.session.add(new_user)
            db.session.commit()
            user_created = 'User: {0} has been created'.format(username)
	    app.logger.info("User %s has been created", username)
            return jsonify({'Created': user_created}),200
    except Exception as e:
	app.logger.error("Error registering user: %s", str(e))
        return jsonify({'Error': str(e.message)}),404

@app.route('/register/customer', methods=['POST'])
def reg_user():
    try:
	app.logger.debug("Received request to register a new customer")
        content = request.json
        if content:
            username = content['username']
	    app.logger.debug("Received username: %s", username)
            password = content['password']
	    app.logger.debug("Received password")
            first_name = content['first_name']
	    app.logger.debug("Received first name: %s", first_name)
            last_name = content['last_name']
	    app.logger.debug("Received last name: %s", last_name)
            email = content['email']
	    app.logger.debug("Received email: %s", email)
            ccn = content.get('ccn')  # ccn is nullable, so use .get() to handle None
            app.logger.debug("Received credit card number: %s", ccn)
	    new_customer = Customer(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password,
                ccn=ccn
            )
            db.session.add(new_customer)
            db.session.commit()
	    app.logger.info("Customer %s has been created", username)
            user_created = 'Customer: {0} has been created'.format(username)
            return jsonify({'Created': user_created}), 200
    except Exception as e:
	app.logger.error("Error registering customer: %s", str(e))
        return jsonify({'Error': str(e)}), 404


@app.route('/login', methods = ['POST'])
def login():
    '''
    You will need to authenticate to this URI first. You will need to pass a JSON body with a username and password key.
    If you enter a valid username and password, a JWT token is returned in the HTTP Response in the Authorization header.
    This token can be used for subsequent requests.
    '''
    try:
	app.logger.debug("Received login request")
        content = request.json
	app.logger.debug("Received request content: %s", content)
        print(content)
        username = content['username']
	app.logger.debug("Received username: %s", username)
        password = content['password']
	app.logger.debug("Received password")
        auth_user = User.query.filter_by(username = username, password = password).first()
        if auth_user:
	    app.logger.debug("Valid user found, generating JWT token")
            auth_token = jwt.encode({'user': username, 'exp': get_exp_date(), 'nbf': datetime.datetime.utcnow(), 'iss': 'we45', 'iat': datetime.datetime.utcnow()}, app.config['SECRET_KEY_HMAC'], algorithm='HS256')
            resp = Response(json.dumps({'Authenticated': True, "User": username}))
            #resp.set_cookie('SESSIONID', auth_token)
            resp.headers['Authorization'] = "{0}".format(auth_token)
            resp.status_code = 200
            resp.mimetype = 'application/json'
            app.logger.info("User %s authenticated successfully", username)
	    return resp
        else:
	    app.logger.warning("Invalid username or password")
            return jsonify({'Error': 'No User here...'}),404
    except:
	app.logger.error("Error in login endpoint: %s", str(e))
        return jsonify({'Error': 'Unable to recognize Input'}),404

@app.route('/fetch/customer', methods=['POST'])
def fetch_customer():
    app.logger.debug("Received request to fetch customer details")
    token = request.headers.get('Authorization')
    app.logger.debug("Authorization header: %s", token)
    if not token or not token.startswith('Bearer '):
	app.logger.warning("Missing or invalid token")
        return jsonify({'Error': 'Missing or invalid token'}), 403

    token = token.split(' ')[1]  # Extract the token by removing 'Bearer '
    app.logger.debug("Token after split: %s", token)

    if not verify_jwt(token):
	app.logger.warning("Invalid token or token expired")
        return jsonify({'Error': 'Invalid token or token expired'}), 403

    # Continue with fetching the customer details
    content = request.json
    app.logger.debug("Request content: %s", content)
    if content:
        customer_id = content['id']
	app.logger.debug("Requested customer ID: %s", customer_id)
        customer_record = Customer.query.get(customer_id)
        if customer_record:
	    app.logger.debug("Customer record found")
            customer_dict = {
                'id': customer_record.id,
                'firstname': customer_record.first_name,
                'lastname': customer_record.last_name,
                'email': customer_record.email,
                'cc_num': customer_record.ccn,
                'username': customer_record.username
            }
	    app.logger.debug("Customer details: %s", customer_dict)
            return jsonify(customer_dict), 200
        else:
	    app.logger.warning("No customer found with the given ID")
            return jsonify({'Error': 'No Customer Found'}), 404
    else:
	app.logger.warning("Invalid request content")
        return jsonify({'Error': 'Invalid Request'}), 400

@app.route('/get/<cust_id>', methods=['GET'])
def get_customer(cust_id):
    try:
        app.logger.debug("Received request for customer ID: {cust_id}")
        token = request.headers.get('Authorization')
        app.logger.debug("Authorization header: {token}")
        if not token or not token.startswith('Bearer '):
            app.logger.warning("Missing or invalid token")
            return jsonify({'Error': 'Missing or invalid token'}), 403

        token = token.split(' ')[1]
        app.logger.debug("Token after split: {token}")

        if not insecure_verify(token):
            app.logger.warning("Invalid Token")
            return jsonify({'Error': 'Invalid Token'}), 403

        if cust_id:
            customer_record = Customer.query.get(cust_id)
            if customer_record:
                customer_dict = {
                    'id': customer_record.id,
                    'firstname': customer_record.first_name,
                    'lastname': customer_record.last_name,
                    'email': customer_record.email,
                    'cc_num': customer_record.ccn,
                    'username': customer_record.username
                }
                app.logger.debug("Customer record found: {customer_dict}")
                return jsonify(customer_dict), 200
            else:
                app.logger.warning("No Customer Found")
                return jsonify({'Error': 'No Customer Found'}), 404
        else:
            app.logger.warning("Invalid Request")
            return jsonify({'Error': 'Invalid Request'}), 400
    except Exception as e:
        app.logger.error("Error in /get/<cust_id>: {e}")
        return jsonify({'Error': 'Internal Server Error'}), 500




@app.route('/search', methods=['POST'])
def search_customer():
    app.logger.debug("Received search request")
    token = request.headers.get('Authorization')
    app.logger.debug("Authorization header: %s", token)
    # Check if token exists and has the correct format
    if not token or not token.startswith('Bearer '):
	app.logger.warning("Missing or invalid token")
        return jsonify({'Error': 'Not Authenticated!'}), 403

    # Extract the token part
    token = token.split(' ')[1]
    app.logger.debug("Token after split: %s", token)
    # Verify JWT token
    if not verify_jwt(token):
	app.logger.warning("Invalid token")
        return jsonify({'Error': 'Invalid Token'}), 403

    # Process the request body
    content = request.json
    app.logger.debug("Request content: %s", content)
    if not content or 'search' not in content:
	app.logger.warning("Invalid request content")
        return jsonify({'Error': 'Invalid Request'}), 400

    # Perform the search based on the 'search' parameter
    try:
        search_term = content['search']
        app.logger.debug("Search term: {}".format(search_term))

        # Example: Direct SQL query (Not recommended due to SQL injection risk)
        str_query = "SELECT first_name, last_name, username FROM customer WHERE username = '{}'".format(search_term)
        search_query = db.engine.execute(str_query)
        results = [list(result) for result in search_query]

        app.logger.debug("Search results: {}".format(results))
        return jsonify(results), 200

    except Exception as e:
        app.logger.error("Error in /search endpoint: {}".format(e))
        return jsonify({'Error': 'Internal Server Error'}), 500


@app.route("/xxe")
def index():
    return render_template(
        'test.html')



@app.route("/xxe_uploader", methods=['POST'])
def hello():
    if request.method == 'POST':
        try:
	    app.logger.debug(json.dumps({"event": "File upload request received"}))
            f = request.files['file']
            if f.filename == '':
		app.logger.warning(json.dumps({"event": "No file selected"}))
                return "No file selected", 400
            
            # Generate a random filename to avoid clashes
            rand = str(random.randint(1, 100))
            fname = secure_filename(f.filename)
            file_path = os.path.join(tempfile.mkdtemp(), rand + '_' + fname)
            app.logger.debug(json.dumps({"event": "Saving file", "file_path": file_path}))

            # Save file locally
            f.save(file_path)
            
	    
            # Access saved file
            document = Document(file_path)
            content = '\n'.join([para.text for para in document.paragraphs])
	    app.logger.debug(json.dumps({"event": "File content extracted"}))

            # Get file details and permissions
            file_stat = os.stat(file_path)
            file_details = {
                "size": file_stat.st_size,
                "permissions": oct(file_stat.st_mode)[-3:],
                "owner": file_stat.st_uid,
                "group": file_stat.st_gid,
                "last_accessed": file_stat.st_atime,
                "last_modified": file_stat.st_mtime,
                "created": file_stat.st_ctime,
                "name": f.filename,
                "format": f.content_type
            }
            log_event = {"event": "File details before deletion", "file_details": file_details}
            app.logger.debug(json.dumps(log_event))

	    # Clean up the temporary directory
            shutil.rmtree(os.path.dirname(file_path))
            app.logger.debug(json.dumps({"event": "Temporary directory cleaned up", "temp_dir": file_path}))
            # Render template with file content
            return render_template('view.html', name=content)
        
        except Exception as e:
	    app.logger.error(json.dumps({"event": "Error processing file", "error": str(e)}))
            return str(e), 400
    
    return "Method not allowed", 405
    app.logger.warning(json.dumps({"event": "Invalid method", "method": request.method}))


@app.route("/yaml")
def yaml_upload():
    return render_template(
        'yaml_test.html')

@app.route("/yaml_hammer", methods = ['POST'])
def yaml_hammer():
    if request.method == "POST":
        f = request.files['file']
        rand = random.randint(1, 100)
        fname = secure_filename(f.filename)
        fname = str(rand) + fname  # change file name
        cwd = os.getcwd()
        file_path = cwd + '/Files/' + fname
        f.save(file_path)  # save file locally

        with open(file_path, 'r') as yfile:
            y = yfile.read()

        ydata = yaml.load(y)

    return render_template('view.html', name = json.dumps(ydata))



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(app_port)
    IOLoop.instance().start()
    # app.run(debug = True, host = '0.0.0.0', port = app_port)
