from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
from sqlite3 import Error
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Create database connection
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('database.db')
    except Error as e:
        print(e)
    return conn

# Create table
def create_table():
    conn = create_connection()
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            role TEXT NOT NULL
                        );''')

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        role = request.form['role']
        
        conn = create_connection()
        with conn:
            try:
                conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                             (name, email, hashed_password, role))
                conn.commit()
                flash('User registered successfully!', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email address already exists', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = create_connection()
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cur.fetchone()
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['user_name'] = user[1]
                session['user_role'] = user[4]
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login failed. Check your email and/or password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    elif session['user_role'] == 'photographer':
        return redirect(url_for('photographer_dashboard'))
    elif session['user_role'] == 'customer':
        return redirect(url_for('customer_dashboard'))

@app.route('/photographer/dashboard')
def photographer_dashboard():
    if 'user_id' not in session or session['user_role'] != 'photographer':
        flash('Access Denied!', 'danger')
        return redirect(url_for('login'))
    return render_template('photographerdash.html')

@app.route('/customer/dashboard')
def customer_dashboard():
    if 'user_id' not in session or session['user_role'] != 'customer':
        flash('Access Denied!', 'danger')
        return redirect(url_for('login'))
    return render_template('userdashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('login'))

@app.route('/bookphotog')
def book_photog():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('bookphotog.html')

@app.route('/manageprof')
def manage_profile():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('manageprof.html')

@app.route('/view_review')
def view_review():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('view_review.html')

@app.route('/view_payment')
def view_payment():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('Payment_status.html')

@app.route('/add_feedback')
def add_feedback():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('add_review.html')

@app.route('/manage_user')
def manage_user():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('manageprof_user.html')

@app.route('/print')
def print():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('print_photos.html')

@app.route('/image_hubp')
def image_hubp():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('Imagehub_photgrapher.html')

@app.route('/image_hubu')
def image_hubu():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('Imagehub_user.html')

@app.route('/bookings_user')
def bookings_user():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('mybookings_user.html')

@app.route('/event_order')
def event_order():
    if 'user_id' not in session:
        flash('You are not logged in!', 'danger')
        return redirect(url_for('login'))
    return render_template('view_event_order.html')

@app.route('/confirm_booking', methods=['GET'])
def confirm_booking():
    return render_template('confirm_booking.html')

@app.route('/confirm_payment',methods=['GET'])
def confirm_payment():
    return render_template('confirm_payment.html')

if __name__ == '__main__':
    create_table()
    app.run(debug=True)