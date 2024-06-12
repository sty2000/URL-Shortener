import atexit
from functools import wraps
from flask import Flask, request, jsonify, make_response
from datetime import datetime
import json
import re
import random
import string
import math
import string
import hashlib
import hmac
from myjwt import JsonWebToken, is_valid_url  # import self-defined functions

from flask_sqlalchemy import SQLAlchemy
import os
import sys
import socket
import sqlite3

"""
This is the version for running at local, no more extra replicas
Persisten stroage using Docker Volume.
"""


"""
Initialisation of variables in generating keys

"""
#host_suffix = socket.gethostname()[-1] # last number of hostname str
host_suffix = "0"
REPLICAS = 1

KEY_LENGTH = 2  # 2-digit code as key 
chars_and_nums = string.digits + string.ascii_lowercase # 0-9, a-z
DIGIT_LENGTH = len(chars_and_nums)  

def generate_anchor(host_suffix, KEY_LENGTH):
    for i in range(REPLICAS): 
        if host_suffix == str(i):
            ID_SPACE = pow(DIGIT_LENGTH, KEY_LENGTH) // REPLICAS
            key_anchor = ID_SPACE*i - 1 # -1 for the first key
            my_max = key_anchor + ID_SPACE
            return key_anchor, my_max
    return -1, 0
key_anchor, MAX = generate_anchor(host_suffix, KEY_LENGTH)


# active_ids and deleted_ids are used to manage the IDs
active_ids = set()  
deleted_ids = set()

SALT_LENGTH = 5

app = Flask(__name__)

# enable the portability with detecting if it is windows system
WIN = sys.platform.startswith('win')
if WIN:
    config_starts = 'sqlite:///'    # windows has the unique prefix
else:
    config_starts = 'sqlite:////'

db_name = './nfs/share/data.db'

# configure database        // URI not URL
app.config['SQLALCHEMY_DATABASE_URI'] = config_starts + os.path.join(app.root_path, db_name)      # /// for windows, or ////
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'OurGroupNumberIs16'  


connection= sqlite3.connect(db_name)
cursor = connection.cursor()
cursor.execute('''DROP TABLE IF EXISTS user''')
cursor.execute('''CREATE TABLE user ( id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT, salt TEXT NOT NULL, password TEXT );''')
connection.commit()

db = SQLAlchemy(app)

jwt_api = JsonWebToken()


# create database model
class User(db.Model):
    #__tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    email = db.Column(db.String)
    salt = db.Column(db.String)
    password = db.Column(db.String)

# generate the random salt
def random_salt():
    return ''.join(random.choice(chars_and_nums) for i in range(SALT_LENGTH))

# hash the password with the salt
def hash_password(salt, pwd):
    salted_pwd = pwd + salt
    hashed_pwd = hashlib.sha256(salted_pwd.encode())
    return hashed_pwd.hexdigest()

# decorator for authenticating the token
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # find the authorization header which contains the token
        auth_header = request.headers.get('Authorization', None)
        if not auth_header:
            print("Token is missing!")
            return jsonify({'message': 'Token is missing!'}), 403
        
        try:
            token_type, token = auth_header.split(' ')
            if token_type.lower() != 'bearer':
                raise ValueError("Authorization header must start with Bearer")
            # compare the old signature with the newly generated one
            if not jwt_api.verify_jwt(token):
                raise ValueError("Invalid token or token has expired")
        except Exception as e:
            print("exception,",e)
            return jsonify({'message': str(e)}), 403

        # decode the payload of the token
        current_user = jwt_api.decode_jwt(token)
        # let POST and PUT receive the current_user
        if request.method == 'POST' or request.method == 'PUT' or request.method == 'DELETE':
            return f(current_user, *args, **kwargs)
        return f( *args, **kwargs)
    
    return decorated_function


"""
Generating IDs:
Starts from 2-digit code as key: _ _, one digit varys from 0 to 9 and a to z.
If the length of key cannot satisfy to represent the number of URLs, the digit length of key will expand.
Deleted ID will be recycled by adding into the [deleted_ids]
"""
def generate_key():
    global key_anchor, KEY_LENGTH, MAX
    if deleted_ids:
        # First will try to reuse recycled IDs
        key = deleted_ids.pop()
    else:
        # Expand the digit length of ID if necessary
        if key_anchor >= MAX - 1:
            KEY_LENGTH += 1
            key_anchor, MAX = generate_anchor(host_suffix, KEY_LENGTH)
        # refresh the key_anchor for the next key
        key_anchor += 1
        # Convert the key_anchor to the key
        key_indices = [(key_anchor // pow(DIGIT_LENGTH, i)) % DIGIT_LENGTH for i in range(KEY_LENGTH - 1, -1, -1)]
        key = ''.join(chars_and_nums[k] for k in key_indices)
    active_ids.add(key)  
    return key

"""
Recycle of deleted IDs:
Delete the ID from [activat_ids] and put it into the [deleted_ids]
"""
def delete_id(del_id):
    if del_id in active_ids:
        active_ids.remove(del_id)
        deleted_ids.add(del_id)
    else:
        print(f"ID '{del_id}' not found.")


"""
Validate the username and password using POST method
return (JWT, 200) if both are correct
       ("forbidden", 403) if any of them are incorrect or not exist or omitted
"""
@app.route('/users/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'username' in data and 'password' in data:
        res = User.query.filter_by(username=data['username']).all()
        if len(res) == 1:
            res = res[0]
            if hmac.compare_digest(hash_password(res.salt, data['password']), res.password):    # compare hashed password
                # generate token
                jwt = jwt_api.generate_jwt(data['username'])  # add the username for verification
                return jsonify(jwt), 200 
            return jsonify({"detail":"forbidden"}), 403 
    else:
        return jsonify({"detail":"forbidden"}), 403

"""
Create an account with POSTed username and password
Return (201) if successfully created
       ("duplicate", 409) if the username was already occupied
       ("username or password not given", 404) if the username or password is not given
"""
@app.route('/users', methods=['POST'])
def users_post():
    #data = request.form
    data = request.get_json()
    if 'username' in data and 'password' in data:
        # res = db.session.execute(db.select(User).filter_by(username=data['username'])).first()
        res = User.query.filter_by(username=data['username']).first()
        if res:
            return jsonify({"detail":"duplicate"}), 409  #make_response(jsonify('duplicate', 409))
        else: 
            # idea: generate a random salt for each user to encrypt the password in case of an attack
            user_salt = random_salt()
            new_user = User(username=data['username'], password=hash_password(user_salt, data['password']), salt=user_salt)
            db.session.add(new_user)
            db.session.commit()
            return jsonify(data['username']), 201
    else:
        return jsonify({"detail":"username or password not given"}), 404 

"""
Get all the users
"""    
@app.route('/users', methods=['GET'])
def users_get():
    users = User.query.all()
    users_data = [{'username': user.username, 'email': user.email} for user in users]
    return jsonify(users_data)

"""
Update the password of the given username using PUT method
Return (200) if successfully updated
       (404) if the username does not exist
       (400) if the username or password is not given
       (403) if the provided old password is incorrect
"""
@app.route('/users', methods=['PUT'])
def users_put():
    data = request.get_json()
    username = data.get('username')
    old_password = data.get('password')
    new_password = data.get('new_password')
    
    if not username or not new_password or not old_password:
        # the username or password is not given
        return jsonify({"detail":"Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        if not hmac.compare_digest(user.password, hash_password(user.salt, old_password)):
            return jsonify({'detail': 'forbidden'}), 403
        user.password = new_password
        db.session.commit()
        return jsonify(user.username), 200
    else:
        # user does not exist
        return jsonify({"detail":"Username does not exist"}), 404

# update urls locally
def load_urls():
    try:
        with open("./nfs/share/urls.txt", "r") as file:
            return dict(line.strip().split(',', 1) for line in file if ',' in line) #dict(line.strip().split(',', 1) for line in file if ',' in line)
    except FileNotFoundError:
        return {}

def save_url(short_id, original_url, user):
    with open("./nfs/share/urls.txt", "a") as file:
        file.write(f"{short_id},{original_url},{user}\n")

def delete_url(short_id):
    urls = load_urls()
    if short_id in urls:
        del urls[short_id]
        with open("./nfs/share/urls.txt", "w") as file:
            for id, url in urls.items():
                file.write(f"{id},{url}\n")
        return True
    return False

def modify_url(short_id, new_url,user):
    urls = load_urls()
    if short_id in urls:
        urls[short_id] = new_url
        with open("./nfs/share/urls.txt", "w") as file:
            for id, url in urls.items():
                file.write(f"{id},{url},{user}\n")
        return True
    return False

def get_all_url():
    urls = load_urls()
    return urls

def get_url_by_id(short_id):
    urls = load_urls()
    if short_id in urls:
        return urls[short_id]
    return None

"""
POST method:
1. Get the URL from the request
2. Check if the URL is valid
3. Generate a unique ID for the URL
4. Store the URL and the author's IP address in the database
5. Return the status code 
"""
@app.route('/', methods=['POST'])
@token_required
def post_by_url(user):
    data = request.get_json()
    url = str(data.get('value'))
    if not is_valid_url(url):
        return make_response({'error': 'Invalid URL'}, 400)
    identifier = generate_key()  # use generate_key() to get ID
    # database[identifier] = {'value': url, 'author': user}
    save_url(identifier, url, ' ' + user)

    return make_response(jsonify(id=identifier, username=user), 201)

"""
GET method:
1. Get all the keys from the database
2. Serialize the list
3. Return the list of keys and the status code
"""
@app.route('/', methods=['GET'])
@token_required
def get_all_keys():
#    keys_list = json.dumps(list(database.keys()))            # serialize the list
#    result = {'keys': keys_list, 'timestamp': datetime.now()}
   result = get_all_url()
#    print(result)
   # 去掉author
   new_res = {key: value.split(',')[0].strip() for key, value in result.items()}
#    print(new_res)
   return make_response(new_res, 200)

"""
GET by ID method:
1. Get the ID from the request
2. Check if the ID exists in the database
3. Return the corresponding URL and the status code
"""
@app.route('/<id>', methods=['GET'])
@token_required
def get_by_id(id):           
 
    result = {'timestamp': datetime.now()}
    res_list = get_url_by_id(id)
    if res_list:
        result = {'id': id, 'value': res_list.split(',')[0].strip()}
        print(res_list)
        return make_response(result, 301)
    else:
        return make_response(result, 404)


"""
Update the ID-URL mappings using PUT method
1. Get the ID and URL from the request
2. Check if the URL is valid
3. Modify the URL if necessary
4. Update the ID-URL mapping in the database
5. Return the status code
Fetching the client ip address with reference at: https://stackoverflow.com/questions/3759981/get-ip-address-of-visitors-using-flask-for-python
"""
@app.route('/<id>', methods=['PUT'])
@token_required
def put_by_id(user, id):
    data = request.get_json()
    if(len(id) != 2):
        return make_response({'error': 'ID is not valid'}, 404)
   
    if 'value' in data:
        url = data['value'] 
        res_list = get_url_by_id(id)
        
        if res_list == None:
            return make_response({'error': 'ID not found'}, 404)
        if res_list.split(',')[1].split(' ')[1] != user:
            return make_response({'error': 'Forbidden'}, 403)
        if url.startswith('http://') or url.startswith('https://'):
            modified_url = url
        elif url != "htInvalid_url/":
            modified_url = "http://127.0.0.1:5000/" + url

        else:
            return make_response({'error': 'Invalid URL'}, 400)
        
        if not is_valid_url(modified_url):
            return make_response({'error': 'Invalid URL'}, 400)
        
        if res_list != None:
            client_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
            # database[id] = {'value': url, 'author': user}
            result = {'id': id, 'url': url}
            modify_url(id, url, ' ' + user)
            return make_response(result, 200)
        else:
            return make_response({'error': 'ID not found'}, 404)
    else:
        return make_response({'error': 'URL is not provided'}, 400)


"""
DELETE by ID method:
1. Get the ID from the request
2. Check if the ID exists in the database
3. Delete the ID from the database
4. Return the status code 
"""
@app.route('/<id>', methods=['DELETE'])
@token_required
def delete_by_id(user, id):
    res_list = get_url_by_id(id)

    #  res_list = 00,http://test.com, jane01
    if res_list:
        username = res_list.split(',')[1].split(' ')[1]
        if username != user:
            return make_response({'error': 'Forbidden'}, 403)
        else:
            delete_id(id)  # update the set of active_ids & deleted_ids
            delete_url(id)
            return make_response('', 204)
    else:
        return make_response({'error': 'ID Not Found'}, 404)


"""
DELETE method:
1. Clear the database
2. Return the status code
"""
@app.route('/', methods=['DELETE'])
@token_required
def delete_without_id(user):
    deleted_nums = 0
    has_anything = False
    res_list = get_all_url()
    for key in res_list.keys():
        url = res_list[key]
        url_list = url.split(',')[1].split(' ')
        if url.split(',')[1].split(' ')[1] == user:
            deleted_nums += 1
            has_anything = True
            delete_url(key)
            delete_id(key) 
   
    if deleted_nums == 0 and has_anything:
        return make_response({'error': 'Forbidden'}, 403)
    elif deleted_nums == 0 and not has_anything:
        return make_response({'error': 'ID Not Found'}, 404)
    result = { 'timestamp': datetime.now()}
    return make_response(result, 404)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
