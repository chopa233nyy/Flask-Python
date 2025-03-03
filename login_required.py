from functools import wraps
from flask import session, flash, redirect, url_for

def login_required(f):
    """Decorator to restrict access to authenticated users only."""
    @wraps(f)  # This fixes the overwriting issue
    def wrap(*args, **kwargs):
        if 'user' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap