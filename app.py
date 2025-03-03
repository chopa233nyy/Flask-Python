"""
Cybersecurity Awareness Web Application
This Flask web application provides information and resources on cybersecurity best practices.
"""

from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from login_required import login_required  # Import the decorator

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Using a persistent dictionary (in a real app, you'd use a database)
users = {}

def is_valid_password(password):
    """Ensure password meets complexity requirements."""
    return (
        len(password) >= 12
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(c in '!@#$%^&*()-+=' for c in password)
    )

@app.route('/')
def home():
    """Render the home page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('home.html', current_time=current_time, user=session.get('user'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            flash('Username already exists! Choose another.', 'danger')
        elif not is_valid_password(password):
            flash(
                'Password must be at least 12 characters long, '
                'including uppercase, lowercase, number, and special character.',
                'danger'
            )
        else:
            users[username] = generate_password_hash(password)
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('register.html', current_time=current_time)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if 'user' in session:
        # Already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username], password):
            session['user'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials. Try again.', 'danger')

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('login.html', current_time=current_time)

@app.route('/dashboard')
@login_required
def dashboard():
    """Display user dashboard."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('dashboard.html', user=session.get('user'), current_time=current_time)

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/about')
@login_required
def about():
    """Display about page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('about.html', user=session.get('user'), current_time=current_time)

@app.route('/contact')
@login_required
def contact():
    """Display contact page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('contact.html', user=session.get('user'), current_time=current_time)

@app.route('/resources')
@login_required
def resources():
    """Display resources page."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('resources.html', user=session.get('user'), current_time=current_time)

if __name__ == '__main__':
    app.run(debug=True)
    