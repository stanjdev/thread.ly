from sqlalchemy_utils import URLType

from threadly.extensions import db
from threadly.utils import FormEnum
from flask_login import UserMixin

from sqlalchemy.sql import func

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    threads = db.relationship('Thread', back_populates='created_by')

class Thread(db.Model):
    """Thread model."""
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.Text)
    image_url = db.Column(db.String, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', back_populates='threads')
    comments = db.relationship('Comment', back_populates='thread')
    # comments = db.relationship('Comment', secondary='thread_comment', back_populates='thread')

# thread_comment_table = db.Table('thread_comment',
#     db.Column('thread_id', db.Integer, db.ForeignKey('thread.id')),
#     db.Column('comment_id', db.Integer, db.ForeignKey('comment.id')),
# )

class Comment(db.Model):
    """Comment model. """
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User')
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)
    thread = db.relationship('Thread', back_populates='comments')
    # thread = db.relationship('Thread', secondary='thread_comment', back_populates='comments')
    last_time = db.Column(db.TIMESTAMP, server_default=func.now(), onupdate=func.current_timestamp())


db.create_all()
