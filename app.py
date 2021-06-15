from flask import Flask, jsonify, request, make_response
import base64
import jwt
import datetime
from functools import wraps
app = Flask(__name__)

app.config['SECRET_KEY'] = 'Very Secret'

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message' : 'There is no token'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message' : 'INVALID TOKEN'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/unprotected')
def unprotected():
    return jsonify({'message' : 'Everybody can see this message'})




@app.route('/protected')
@token_required
def protected():
    with open("Secret_logo.jpg", "rb") as image_file:
        message_string = base64.b64encode(image_file.read())
    return jsonify({'img' :  str(message_string.decode('utf-8'))})


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get("username", "lol")
    password = request.form.get("password", "lol")
    print(username)
    print(password)
    # auth = request.authorization    
    if username == "1" and password == "1":
        token = jwt.encode({'user' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=40)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})    
    return make_response('Could not verify!',401, {'WWW-Authenticate' : 'Basic realm="Login Required"'})


if __name__ == '__main__':
    app.run(debug=True)