from flask import *
from sqlalchemy import ForeignKey
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, LoginManager, current_user, login_user, logout_user
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, send, emit
import config


app = Flask(__name__)
app.config['SECRET_KEY'] = config.app_key
socketio = SocketIO(app, cors_allowed_origins='*')
Bootstrap5(app)

ALLOWED_EXTENSIONS = {'png', 'jpg'}
app.config['SQLALCHEMY_DATABASE_URI'] = config.database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = config.uploads
app.config.update(GEOIPIFY_API_KEY=config.app_key)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(30), nullable=False, unique=False)
    lname = db.Column(db.String(30), nullable=False, unique=False)
    email = db.Column(db.String(50), unique=True)
    username = db.Column(db.Text, unique=True)
    password = db.Column(db.String(1000))
    user_image = db.Column(db.String, nullable=True)
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(1000), nullable=True)
    posts = relationship('Posts', back_populates='username')


class Posts(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    username = relationship('Users', back_populates='posts')
    pet_name = db.Column(db.String(1000), nullable=False)
    pet_type = db.Column(db.String(1000), nullable=False)
    pet_specie = db.Column(db.String(1000), nullable=False)
    pet_about = db.Column(db.String(1000), nullable=False)
    date = db.Column(db.String(1000), nullable=False)
    image = db.Column(db.String, nullable=False)
    location = db.Column(db.String(1000), nullable=True)


with app.app_context():
    db.create_all()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def home():
    return render_template(
        'index.html',
        logged_in=current_user.is_authenticated,
        current_user=current_user
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = request.args.get('error')
    all_users = db.session.query(Users).all()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        verify_username = Users.query.filter_by(username=username).first()
        if verify_username in all_users:
            checked_password = check_password_hash(verify_username.password, password)
            if checked_password:
                ll = verify_username.id
                login_user(verify_username)
                return redirect(
                    url_for(
                        'dashboard',
                        logged_in=current_user.is_authenticated,
                        ll=ll)
                )
            else:
                error = 'Invalid Password'
                return redirect(url_for('login', error=error))
        else:
            error = 'Invalid Username'
            return redirect(url_for('login', error=error))
    return render_template('login.html', error=error)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = request.args.get('error')
    all_users = db.session.query(Users).all()
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        verify_email = Users.query.filter_by(email=email).first()
        if verify_email in all_users:
            error = 'This email address is already in use. Login instead?'
            return redirect(url_for('login', error=error))
        verify_username = Users.query.filter_by(username=username).first()
        if verify_username in all_users:
            error = 'This username is already taken. Try another one'
            return redirect(url_for('signup', error=error))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = Users(
            fname=fname.title(),
            lname=lname.title(),
            email=email,
            username=username,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login', user=new_user))
    return render_template('signup.html', error=error)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = int(request.args.get('ll'))
    user = Users.query.filter_by(id=user_id).first()
    posts = Posts.query.filter_by(user_id=user_id).all()
    if request.method == 'POST':
        pet_name = request.form['petname']
        pet_type = request.form['type']
        pet_specie = request.form['specie']
        about = request.form['about']
        file = request.files['image_upload']
        today = datetime.now()
        day = today.day
        year = today.year

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            date = f"{day} {today.strftime('%b')}, {year}"
            new_post = Posts(
                pet_name=pet_name.title(),
                username=current_user,
                pet_type=pet_type.title(),
                pet_specie=pet_specie.title(),
                pet_about=about,
                location=user.location,
                date=date,
                image=filename
            )
            db.session.add(new_post)
            db.session.flush()
            db.session.commit()
            return redirect(
                url_for(
                    'dashboard',
                    ll=user_id,
                    user=user,
                    logged_in=current_user.is_authenticated,
                    posts=posts,
                    current_user=current_user)
            )

    return render_template(
        'dashboard.html',
        user=user,
        logged_in=current_user.is_authenticated,
        posts=posts
    )


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    user_id = request.args.get('user')
    user = Users.query.filter_by(id=user_id).first() 
    posts = Posts.query.filter_by(user_id=user_id).all()
   
    if request.method == 'POST':
        file = request.files['image_upload']
        if file.filename == '':
            pass
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.user_image = filename
            db.session.commit()
        user.fname = request.form.get('fname')
        user.lname = request.form.get('lname')
        user.email = request.form.get('email')
        user.bio = request.form.get('bio')
        user.location = request.form.get('loc')
        db.session.commit()
        for post in posts:
            post.location = user.location
            db.session.commit()
        return redirect(
            url_for(
                'dashboard',
                ll=user_id,
                user=user,
                logged_in=current_user.is_authenticated,
                posts=posts)
        )

    return render_template('edit_page.html', user=user)



@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():
    user_id = request.args.get('user')
    user = Users.query.filter_by(id=user_id).first()
    user_loc = user.location
    all_posts = Posts.query.filter_by(location=user_loc).all()
    return render_template(
        'feed.html',
        posts=all_posts,
        logged_in=current_user.is_authenticated,
        user=user,
        feed=True
    )


@app.route('/post')
@login_required
def post():
    post_id = request.args.get('post_id')
    user_id = int(request.args.get('ll'))
    post = Posts.query.filter_by(id=post_id).first()
    post_author = Users.query.filter_by(id=post.user_id).first()
    user = Users.query.filter_by(id=user_id).first()
    user_loc = user.location
    all_posts = Posts.query.filter_by(location=user_loc).all()
    return render_template(
        'post.html',
        post=post,
        posts=all_posts,
        user=user,
        logged_in=current_user.is_authenticated,
        auth=post_author
    )


def messageReceived():
    print('message was received!!!')


@socketio.on('my event')
def handle_my_custom_event(json):
    print('received my event: ' + str(json))
    socketio.emit('my response', json, callback=messageReceived)



@app.route('/dm', methods=['GET'])
@login_required
def contact():
    username = request.args.get('em')
    return render_template('contact.html')


if __name__ == '__main__':
    socketio.run(app, debug=True)
