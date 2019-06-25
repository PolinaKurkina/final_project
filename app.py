from flask import Flask, request, jsonify, make_response, redirect
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import random
import string
from functools import wraps


app = Flask(__name__)


app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///C:\Users\Полина\Desktop\final task\db.db'


db = SQLAlchemy(app)


class User(db.Model):
    id_user = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))

     
class Url(db.Model):
    id_url = db.Column(db.Integer, primary_key=True)
    id_user = db.Column(db.Integer, db.ForeignKey(User.id_user))
    long_url = db.Column(db.String(80))
    short_url = db.Column(db.String(50))
    nickname = db.Column(db.String(50))
    clicks = db.Column(db.Integer)
    access = db.Column(db.String(50))


def shorten_url():
    short_url = ''.join(random.choice(string.digits + string.ascii_lowercase
                  + string.ascii_uppercase) for _ in range(random.randint(8, 12)))
    return short_url


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
      token = request.cookies.get('token')
      if not token:
            current_user = 'guest'
            return f(current_user, *args, **kwargs)
      try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id_user=data['id_user']).first()
      except:
            return jsonify({'message' : 'Token is invalid!'}), 401

      return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id_user'] = user.id_user
        user_data['username'] = user.username
        user_data['password'] = user.password
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<id_user>', methods=['GET'])
@token_required
def get_one_user(current_user, id_user):


    user = User.query.filter_by(id_user=id_user).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['id_user'] = user.id_user
    user_data['username'] = user.username
    user_data['password'] = user.password


    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    new_user = User(username=data['username'], password=data['password'],)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


@app.route('/user/<id_user>', methods=['DELETE'])
@token_required
def delete_user(current_user, id_user):

    user = User.query.filter_by(id_user = id_user).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if user.password == auth.password:
        token = jwt.encode({'id_user': user.id_user, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        res = make_response()
        res.set_cookie("token", value = token, max_age = None)
        return res

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})  


@app.route('/url', methods=['GET'])
@token_required
def get_all_urls(current_user):
    if current_user is 'guest':
        return jsonify({"message": "Cannot perform that action!"})

    urls = Url.query.filter_by(id_user=current_user.id_user).all()

    output = []

    for url in urls:
        url_data = {}
        url_data['id_url'] = url.id_url
        url_data['id_user'] = url.id_user
        url_data['long_url'] = url.long_url
        url_data['short_url'] = url.short_url
        url_data['nickname'] = url.nickname
        url_data['clicks'] = url.clicks
        url_data['access'] = url.access
        output.append(url_data)

    return jsonify({'urls': output})


@app.route('/url/<id_url>', methods=['GET'])
@token_required
def get_one_url(current_user, id_url):
    if current_user is 'guest':
        return jsonify({"message": "Cannot perform that action!"})

    url = Url.query.filter_by(id_url=id_url, id_user=current_user.id_user).first()

    if not url:
        return jsonify({'message': 'No url found!'})

    url_data = {}
    url_data['id_url'] = url.id_url
    url_data['id_user'] = url.id_user
    url_data['long_url'] = url.long_url
    url_data['short_url'] = url.short_url
    url_data['nickname'] = url.nickname
    url_data['clicks'] = url.clicks
    url_data['access'] = url.access

    return jsonify(url_data)


@app.route('/url', methods=['POST'])
@token_required
def create_url(current_user):
    data = request.get_json()
    if data['nickname'] == "":
        s_url = shorten_url()
    else:
        s_url = data['nickname']
    if current_user is 'guest':
       new_url = Url(long_url = data['long_url'],
                     short_url = s_url,
                     nickname = data['nickname'],
                     clicks = 0,
                     access = 'public',)
    else:    
        new_url = Url(id_user = current_user.id_user,
                     long_url = data['long_url'],
                     short_url = s_url,
                     nickname = data['nickname'],
                     clicks = 0,
                     access = data['access'],)
    db.session.add(new_url)
    db.session.commit()

    return jsonify({'message' : "Url created!"})


@app.route('/url/<id_url>', methods=['PUT'])
@token_required
def change_url(current_user, id_url):
    if current_user is 'guest':
        return jsonify({"message": "Cannot perform that action!"})

    data = request.get_json()
    url = Url.query.filter_by(id_url=id_url, id_user=current_user.id_user).first()

    if not url:
        return jsonify({'message' : 'No url found!'})

    url.short_url = data['nickname']
    url.nickname = data['nickname']
    url.access = data['access']
    db.session.commit()

    return jsonify({'message' : 'Url item has been changed!'})


@app.route('/url/<id_url>', methods=['DELETE'])
@token_required
def delete_url(current_user, id_url):
    if current_user is 'guest':
        return jsonify({"message": "Cannot perform that action!"})
    url = Url.query.filter_by(id_url=id_url, id_user=current_user.id_user).first()

    if not url:
        return jsonify({'message': 'No url found!'})

    db.session.delete(url)
    db.session.commit()

    return jsonify({'message' : 'Url item deleted!'})


def redirect_url(url):
     long_url = url.long_url
     url.clicks = url.clicks +1
     db.session.commit()
     return redirect(long_url, code=302)


@app.route('/<short_url>')
@token_required
def catch_all(current_user, short_url):
    url = Url.query.filter_by(short_url=short_url).first()
    if not url:
        return jsonify({'message': 'No url found!'})

    else:
            if url.access == 'public':
               return redirect_url(url)
            elif url.access == 'sharing':
                 if current_user is not 'guest':
                    return redirect_url(url)
                 else: 
                    return jsonify({'message': 'Access restricted!'})
            if url.access == 'private':
                if current_user is not 'guest' and current_user.id_user == url.id_user:
                    return redirect_url(url)
                else: 
                    return jsonify({'message': 'Access restricted!'})
            

if __name__ == '__main__':
    app.run(debug=True)
