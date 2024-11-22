from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField
from wtforms.validators import InputRequired, Length, EqualTo, Email, NumberRange

app = Flask(__name__)


app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MONGO_URI'] = 'mongodb+srv://smartparking:smart%40123@cluster0.ipeb8.mongodb.net/'


client = MongoClient(app.config['MONGO_URI'])
db = client.smart_parking
users_collection = db.users
parking_spots_collection = db.parking_spots

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])  
        self.email = user_data['email']
        self.is_organizer = user_data['is_organizer']

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class SearchForm(FlaskForm):
    location = StringField('Location', validators=[InputRequired()])

class AddParkingSpotForm(FlaskForm):
    location = StringField('Location', validators=[InputRequired()])

class EditProfileForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])

class BookParkingSpotForm(FlaskForm):
    duration = IntegerField('Duration (hours)', validators=[InputRequired(), NumberRange(min=1)])

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None


class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=6, max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message="Passwords must match")])

@app.route('/')
def home():
    return render_template('base.html')


@app.route('/signup_user', methods=['GET', 'POST'])
def signup_user():
    form = SignupForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        if users_collection.find_one({"email": email}):
            flash('Email is already in use.', 'danger')
            return redirect(url_for('signup_user'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {
            "email": email,
            "password": hashed_password,
            "is_organizer": False
        }
        users_collection.insert_one(user)
        flash('User account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup_user.html', form=form)


@app.route('/signup_organizer', methods=['GET', 'POST'])
def signup_organizer():
    form = SignupForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        if users_collection.find_one({"email": email}):
            flash('Email is already in use.', 'danger')
            return redirect(url_for('signup_organizer'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = {
            "email": email,
            "password": hashed_password,
            "is_organizer": True
        }
        users_collection.insert_one(user)
        flash('Organizer account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup_organizer.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_organizer:
            return redirect(url_for('dashboard_organizer'))
        return redirect(url_for('dashboard_user'))

    form = LoginForm()  

    if form.validate_on_submit():  
        email = form.email.data
        password = form.password.data
        user = users_collection.find_one({"email": email})

        if user and bcrypt.check_password_hash(user['password'], password):
            user_obj = User(user)
            login_user(user_obj)
            flash('Login successful!', 'success')
            if user['is_organizer']:
                return redirect(url_for('dashboard_organizer'))
            return redirect(url_for('dashboard_user'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')

    return render_template('login.html', form=form)  



@app.route('/dashboard_user', methods=['GET', 'POST'])
@login_required
def dashboard_user():
    if current_user.is_organizer:
        return redirect(url_for('dashboard_organizer'))

    form = SearchForm()  
    spots = list(parking_spots_collection.find({"availability": True}))

    
    if form.validate_on_submit():
        location = form.location.data
        spots = list(parking_spots_collection.find({
            "location": {"$regex": location, "$options": "i"},
            "availability": True
        }))
        flash(f"Found {len(spots)} spots for '{location}'", 'success')

    return render_template('dashboard_user.html', form=form, spots=spots)


@app.route('/dashboard_organizer', methods=['GET', 'POST'])
@login_required
def dashboard_organizer():
    if not current_user.is_organizer:
        return redirect(url_for('dashboard_user'))

    form = AddParkingSpotForm()  

    if form.validate_on_submit():  
        location = form.location.data
        try:
            lat, lng = map(float, location.split(','))
        except ValueError:
            flash('Invalid location format. Use "latitude,longitude".', 'danger')
            return redirect(url_for('dashboard_organizer'))

        parking_spot = {"location": f"{lat},{lng}", "availability": True}
        parking_spots_collection.insert_one(parking_spot)
        flash('Parking spot added successfully!', 'success')
        return redirect(url_for('dashboard_organizer'))

    parking_spots = list(parking_spots_collection.find())
    return render_template('dashboard_organizer.html', form=form, parking_spots=parking_spots)



@app.route('/add_parking_spot', methods=['GET', 'POST'])
@login_required
def add_parking_spot():
    if not current_user.is_organizer:
        flash('Only organizers can add parking spots.', 'danger')
        return redirect(url_for('dashboard_user'))

    if request.method == 'POST':
        
        manual_lat = request.form.get('manual_lat')
        manual_lng = request.form.get('manual_lng')
        map_location = request.form.get('map_location')

        if manual_lat and manual_lng:  
            try:
                lat, lng = float(manual_lat), float(manual_lng)
            except ValueError:
                flash('Invalid manual latitude/longitude format.', 'danger')
                return redirect(url_for('add_parking_spot'))
        elif map_location:  
            try:
                lat, lng = map(float, map_location.split(','))
            except ValueError:
                flash('Invalid map location format.', 'danger')
                return redirect(url_for('add_parking_spot'))
        else:  
            flash('Please provide a location either manually or via the map.', 'danger')
            return redirect(url_for('add_parking_spot'))


        parking_spot = {"location": f"{lat},{lng}", "availability": True}
        parking_spots_collection.insert_one(parking_spot)
        flash('Parking spot added successfully!', 'success')
        return redirect(url_for('dashboard_organizer'))

    
    parking_spots = list(parking_spots_collection.find({"availability": True}))
    return render_template('add_parking_spot.html', parking_spots=parking_spots)



@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()  

    if form.validate_on_submit(): 
        email = form.email.data

        if users_collection.find_one({"email": email, "_id": {"$ne": ObjectId(current_user.id)}}):
            flash('Email is already in use by another account.', 'danger')
            return redirect(url_for('edit_profile'))

       
        users_collection.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"email": email}}
        )
        flash('Your profile has been updated successfully!', 'success')
        return redirect(url_for('dashboard_user' if not current_user.is_organizer else 'dashboard_organizer'))

    
    form.email.data = current_user.email
    return render_template('edit_profile.html', form=form)


@app.route('/search_parking', methods=['GET', 'POST'])
@login_required
def search_parking():
    if request.method == 'POST':
        location = request.form.get('location')
        spots = list(parking_spots_collection.find({
            "location": {"$regex": location, "$options": "i"},
            "availability": True
        }))
        return render_template('search_parking.html', spots=spots)

    return render_template('search_parking.html', spots=[])


@app.route('/book_parking_spot/<string:spot_id>', methods=['GET', 'POST'])
@login_required
def book_parking_spot(spot_id):
    spot = parking_spots_collection.find_one({"_id": ObjectId(spot_id)})

    if not spot:
        flash('Parking spot not found.', 'danger')
        return redirect(url_for('dashboard_user'))

    form = BookParkingSpotForm()  

    if form.validate_on_submit(): 
        duration = form.duration.data

        
        parking_spots_collection.update_one(
            {"_id": ObjectId(spot_id)},
            {"$set": {"availability": False}}
        )

        
        flash(f'Parking spot booked for {duration} hours!', 'success')
        return redirect(url_for('dashboard_user'))

    return render_template('book_parking_spot.html', form=form, spot=spot)


@app.route('/logout')
@login_required 
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
