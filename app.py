from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_parking.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'  # for better message category in flash messages

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_organizer = db.Column(db.Boolean, default=False)  # True if Organizer, False if regular User

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(150), nullable=False)  # Store as "(lat, lng)"
    availability = db.Column(db.Boolean, default=True)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('base.html')

# User Signup Route
@app.route('/signup_user', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user:  # Ensure the email is unique
            flash('Email is already in use.', 'danger')
            return redirect(url_for('signup_user'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, is_organizer=False)
        db.session.add(user)
        db.session.commit()
        flash('User account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup_user.html')

# Organizer Signup Route
@app.route('/signup_organizer', methods=['GET', 'POST'])
def signup_organizer():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user:  # Ensure the email is unique
            flash('Email is already in use.', 'danger')
            return redirect(url_for('signup_organizer'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password, is_organizer=True)
        db.session.add(user)
        db.session.commit()
        flash('Organizer account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('signup_organizer.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Check if the user is already logged in
        if current_user.is_organizer:
            return redirect(url_for('dashboard_organizer'))
        else:
            return redirect(url_for('dashboard_user'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            # Redirect to the appropriate dashboard based on user role
            if user.is_organizer:
                return redirect(url_for('dashboard_organizer'))
            else:
                return redirect(url_for('dashboard_user'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

# User Dashboard
@app.route('/dashboard_user')
@login_required
def dashboard_user():
    if current_user.is_organizer:  # Ensure only regular users can access this route
        return redirect(url_for('dashboard_organizer'))
    
    # Fetch available parking spots
    spots = ParkingSpot.query.filter_by(availability=True).all()
    return render_template('dashboard_user.html', spots=spots)

# Organizer Dashboard
@app.route('/dashboard_organizer')
@login_required
def dashboard_organizer():
    if not current_user.is_organizer:  # Ensure only organizers can access this route
        return redirect(url_for('dashboard_user'))
    return render_template('dashboard_organizer.html')

# Add Parking Spot (Organizer Route)
@app.route('/add_parking_spot', methods=['GET', 'POST'])
@login_required
def add_parking_spot():
    if not current_user.is_organizer:
        return redirect(url_for('dashboard_user'))

    if request.method == 'POST':
        location = request.form.get('location')
        # Split the location into latitude and longitude
        try:
            lat, lng = map(float, location.split(','))
        except ValueError:
            flash('Invalid location format. Please drag the marker to select a valid location.', 'danger')
            return redirect(url_for('add_parking_spot'))

        # Add new parking spot to the database
        new_spot = ParkingSpot(location=f'{lat},{lng}', availability=True)
        db.session.add(new_spot)
        db.session.commit()
        flash('Parking spot added successfully!', 'success')
        return redirect(url_for('add_parking_spot'))

    # Fetch all parking spots from the database to display on the map
    parking_spots = ParkingSpot.query.filter_by(availability=True).all()
    spots_data = [{'location': spot.location, 'lat': spot.location.split(',')[0], 'lng': spot.location.split(',')[1]} for spot in parking_spots]

    return render_template('add_parking_spot.html', parking_spots=spots_data)

# Edit Profile Route
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            current_user.email = email
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('dashboard_user' if not current_user.is_organizer else 'dashboard_organizer'))
    
    return render_template('edit_profile.html', user=current_user)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Search Parking Route
@app.route('/search_parking', methods=['GET', 'POST'])
@login_required
def search_parking():
    if request.method == 'POST':
        location = request.form.get('location')
        spots = ParkingSpot.query.filter(ParkingSpot.location.ilike(f'%{location}%'), ParkingSpot.availability == True).all()
        return render_template('search_parking.html', spots=spots)
    
    return render_template('search_parking.html', spots=[])

# Book Parking Spot Route
@app.route('/book_parking_spot/<int:spot_id>', methods=['GET', 'POST'])
@login_required
def book_parking_spot(spot_id):
    spot = ParkingSpot.query.get_or_404(spot_id)
    if request.method == 'POST':
        # Add booking logic here (e.g., update availability or save to a booking table)
        spot.availability = False  # Mark the spot as booked
        db.session.commit()
        flash('Parking spot booked successfully!', 'success')
        return redirect(url_for('dashboard_user'))
    return render_template('book_parking_spot.html', spot=spot)

if __name__ == '__main__':
    app.run(debug=True)
