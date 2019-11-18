from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow,  onupdate=datetime.utcnow)

    files = db.relationship('File', backref='user')
    accesses = db.relationship('FileAccess', backref='user')


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.username)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    hash = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    timestamp_created = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    accesses = db.relationship('FileAccess', backref='file')

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<{}:{}>".format(id, self.name)


class FileAccess(db.Model):
    __tablename__ = 'accesses'
    id = db.Column(db.Integer, primary_key=True)
    when_timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    file_id = db.Column(db.Integer(), db.ForeignKey('files.id'))
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))

    def __str__(self):
        return self.who

    def __repr__(self):
        return "<{}:{}>".format(id, self.who)
