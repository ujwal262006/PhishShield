"""Shared Flask extension instances.

Kept in a separate module to avoid circular imports between the app factory
and the models/routes that need these objects.
"""
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Redirect unauthenticated browser users to the login page.
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
