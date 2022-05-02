from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from threadly.config import Config
import os

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
