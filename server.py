# coding: utf-8
from datetime import datetime, timedelta
from flask import g, render_template, request, jsonify, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_sqlalchemy
from flask_oauthlib.contrib.oauth2 import bind_cache_grant
import json
from werkzeug.security import gen_salt

db = SQLAlchemy()

users2rooms = db.Table('user_room',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('room_id', db.Integer, db.ForeignKey('room.id'))
)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    creator = db.relationship('User', backref=db.backref('user_messages'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    host_room = db.relationship('Room', backref=db.backref('room_messages'))

    def __init__(self, creator: "User", room: "Room", text: str):
        self.text = text
        self.creator = creator
        self.host_room = room


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    creator = db.relationship('User')
    users = db.relationship('User', secondary=users2rooms,
                            backref=db.backref('rooms', lazy='dynamic'))

    def __init__(self, room_name, creator: "User"):
        self.name = room_name
        self.creator = creator
        self.users.append(creator)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, index=True,
                         nullable=False)
    password = db.Column(db.String(40), nullable = False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def check_password(self, password):
        return self.password == password

    def write_to_room(self, room: "Room", text: str):
        if self in room.users:
            print("saving message")
            m = Message(self, room, text)
            db.session.add(m)
            db.session.commit()
            return True
        return False

class Client(db.Model):
    # id = db.Column(db.Integer, primary_key=True)
    # human readable name
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), unique=True, index=True,
                              nullable=False)
    client_type = db.Column(db.String(20), default='public')
    redirect_uri = db.Column(db.Text)

    default_scope = db.Column(db.Text, default='email address')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', uselist=False,  backref=db.backref('client', uselist=False) )

    def __init__(self, user:"User", redirect_uri):
        self.client_id = gen_salt(40)
        self.client_secret = gen_salt(50)
        self.user = user
        self.redirect_uri = redirect_uri
        self.client_type = 'public'

    @property
    def redirect_uris(self):
        if self.redirect_uri:
            return [self.redirect_uri, ]
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uri

    @property
    def default_scopes(self):
        if self.default_scope:
            return self.default_scope.split()
        return []

    @property
    def allowed_grant_types(self):
        return ['authorization_code', 'password', 'client_credentials',
                'refresh_token']


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    client = relationship('Client')
    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    scope = db.Column(db.Text)
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return None


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id', ondelete='CASCADE'),
        nullable=False,
    )
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = relationship('User')
    client = relationship('Client')
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255))
    refresh_token = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    scope = db.Column(db.Text)

    def __init__(self, **kwargs):
        expires_in = kwargs.pop('expires_in')
        self.expires = datetime.utcnow() + timedelta(seconds=expires_in)
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def scopes(self):
        if self.scope:
            return self.scope.split()
        return []

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self


def current_user():
    return g.user


def cache_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User,
                    token=Token, client=Client)

    app.config.update({'OAUTH2_CACHE_TYPE': 'simple'})
    bind_cache_grant(app, oauth, current_user)
    return oauth


def sqlalchemy_provider(app):
    oauth = OAuth2Provider(app)

    bind_sqlalchemy(oauth, db.session, user=User, token=Token,
                    client=Client, grant=Grant, current_user=current_user)

    return oauth


def default_provider(app):
    oauth = OAuth2Provider(app)

    @oauth.clientgetter
    def get_client(client_id):
        return Client.query.filter_by(client_id=client_id).first()

    @oauth.grantgetter
    def get_grant(client_id, code):
        return Grant.query.filter_by(client_id=client_id, code=code).first()

    @oauth.tokengetter
    def get_token(access_token=None, refresh_token=None):
        if access_token:
            return Token.query.filter_by(access_token=access_token).first()
        if refresh_token:
            return Token.query.filter_by(refresh_token=refresh_token).first()
        return None

    @oauth.grantsetter
    def set_grant(client_id, code, request, *args, **kwargs):
        expires = datetime.utcnow() + timedelta(seconds=100)
        grant = Grant(
            client_id=client_id,
            code=code['code'],
            redirect_uri=request.redirect_uri,
            scope=' '.join(request.scopes),
            user_id=g.user.id,
            expires=expires,
        )
        db.session.add(grant)
        db.session.commit()

    @oauth.tokensetter
    def set_token(token, request, *args, **kwargs):
        # In real project, a token is unique bound to user and client.
        # Which means, you don't need to create a token every time.
        tok = Token(**token)
        tok.user_id = request.user.id
        tok.client_id = request.client.client_id
        db.session.add(tok)
        db.session.commit()

    @oauth.usergetter
    def get_user(username, password, *args, **kwargs):
        # This is optional, if you don't need password credential
        # there is no need to implement this method
        return User.query.filter_by(username=username).first()

    return oauth


def prepare_app(app):
    db.init_app(app)
    db.app = app
    db.create_all()

    user1 = User(username='admin', password="admin")
    user2 = User(username='waiter', password="waiter")

    client1 = Client(user1, 'http://localhost:65010/callback')
    client2 = Client(user2, 'http://localhost:65010/callback')

    try:
        db.session.add(user1)
        db.session.add(user2)
        db.session.add(client1)
        db.session.add(client2)
        #db.session.add(temp_grant)
        #db.session.add(access_token)
        global_room = Room("global", user1)
        db.session.add(global_room)
        global_room.users.append(user1)
        #global_room.users.append(user2)
        db.session.commit()
        user1.write_to_room(global_room, "Hello, World!!!")


    except:
        db.session.rollback()
    return app


def create_server(app, oauth=None):
    if not oauth:
        oauth = default_provider(app)

    app = prepare_app(app)

    @app.before_request
    def load_current_user():
        user = User.query.get(1)
        g.user = user


    @app.route('/rooms/<room_name>/users', methods=['GET', 'POST', 'DELETE'])
    @oauth.require_oauth('email')
    def users_resource(room_name):
        room = Room.query.filter_by(name=room_name).first_or_404()

        if request.method == 'GET':
            #print(room_name)
            names = [user.username for user in room.users]
            names_roles = []
            for name in names:
                role = 'user'
                if name == room.creator.username:
                    role = 'admin'
                names_roles.append({"name": name, "role": role})
            return jsonify(names_roles)

        if request.method == 'POST':
            me = request.oauth.user
            if not me in room.users:
                return jsonify({"result": "Error", "description": "Acces denided"})
            username = request.args["username"]
            if username is None:
                return jsonify(result="Error", description="User name parametr was not found")

            user = User.query.filter_by(username=request.args["username"]).first()
            if user is None:
                return jsonify(result="Error", description="User not found")
            if user in room.users:
                return jsonify(result="Error", description="User in room")

            room.users.append(user)
            db.session.commit()
            return jsonify({"result": "Adding user completed"})

        if request.method == 'DELETE':
            me = request.oauth.user
            if me.username != room.creator.username:
                return jsonify({"result": "Error", "description": "Acces denided"})
            username = request.args["username"]
            if username is None:
                return jsonify(result="error", reason="user name was not found")
            user = User.query.filter_by(username).first_or_404()
            if user not in room.users:
                return jsonify(result="error", reason="user was not found in room")
            room.users.remove(user)
            return jsonify(result="Deleting user completed")

    @app.route('/rooms/<room_name>/messages', methods=['GET', 'POST'])
    @oauth.require_oauth('email')
    def messages_resource(room_name):
        room = Room.query.filter_by(name=room_name).first_or_404()
        if request.method == 'GET':
            signed_texts = [dict(author=message.creator.username, text=message.text) for message in room.room_messages]
            resp = Response(response=json.dumps(signed_texts), status=200, mimetype="application/json")
            return resp
            #return jsonify(signed_texts)

        if request.method == 'POST':
            user = request.oauth.user
            if user.write_to_room(room, request.args["text"]):
                return jsonify(result="Message sent successfully")
            else:
                return jsonify(result="Message sending error")

    @app.route('/rooms', methods=['GET', 'POST', 'DELETE'])
    @oauth.require_oauth('email')
    def rooms_resource():
        rooms = Room.query.all()

        if request.method == 'GET':
            content = [dict(name=room.name, people_number=len(room.users)) for room in rooms]
            resp = Response(response=json.dumps(content), status=200, mimetype="application/json")
            return resp

        if request.method == 'POST':
            print("adding room")
            user = request.oauth.user
            room_name = request.args["room_name"]
            if room_name is None:
                return jsonify(result="error", reason="room name was not found")
            room_names = [room.name for room in rooms]
            if room_name in room_names:
                return jsonify(result="error", reason="room was created before")
            room = Room(room_name, user)
            db.session.add(room)
            db.session.commit()
            return jsonify(result="Room added Successfully")

        if request.method == 'DELETE':
            me = request.oauth.user
            room_name = request.args["room_name"]
            if room_name is None:
                return jsonify(result="error", reason="room name was not found")
            room = Room.query.filter_by(room_name).first_or_404()
            if me.username != room.creator.username:
                return jsonify({"result": "Error", "description": "Access denied"})
            db.session.delete(room)
            db.session.commit()
            return jsonify(result="Room deleted Successfully")


    @app.route('/users', methods=['GET', 'POST'])
    def clients_resource():
        if request.method == 'GET':
            names = [dict(name=user.username) for user in User.query.all()]
            resp = Response(response=json.dumps(names), status=200, mimetype="application/json")
            return resp
            # return jsonify(signed_texts)

        if request.method == 'POST':
            username = request.args["username"]
            password = request.args["password"]
            user = User.query.filter_by(username=username).first()
            client = None
            if user is None:
                print("Creating of user")
                user = User(username, password)
                client = Client(user, 'http://localhost:65010/callback')
                db.session.add(user)
                db.session.add(client)
                db.session.commit()
            else:
                if user.check_password(password):
                    client = user.client
                else:
                    return jsonify(result="Error", reason="Incorrect login for real user")
            resp = jsonify(client_id=client.client_id, client_secret=client.client_secret)
            return resp

    @app.route('/oauth/authorize', methods=['GET', 'POST'])
    @oauth.authorize_handler
    def authorize(*args, **kwargs):
        username = request.args["username"]
        password = request.args["password"]
        user = User.query.filter_by(username=username).first_or_404()
        return user.check_password(password)

    @app.route('/oauth/token', methods=['POST', 'GET'])
    @oauth.token_handler
    def access_token():
        return {}

    @app.route('/oauth/revoke', methods=['POST'])
    @oauth.revoke_handler
    def revoke_token():
        pass

    @app.route('/api/email')
    @oauth.require_oauth('email')
    def email_api():
        oauth = request.oauth
        return jsonify(email='me@oauth.net', username=oauth.user.username)

    @app.route('/api/client')
    @oauth.require_oauth()
    def client_api():
        oauth = request.oauth
        return jsonify(client=oauth.client.name)

    @oauth.invalid_response
    def require_oauth_invalid(req):
        return jsonify(message=req.error_message), 401

    return app


if __name__ == '__main__':
    from flask import Flask
    app = Flask(__name__, template_folder='templates')
    app.debug = True

    app.secret_key = 'development'
    app.config.update({
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///test.sqlite'
    })
    app = create_server(app)
    app.run()