from flask import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config.app_key

app.config['SQLALCHEMY_DATABASE_URI'] = config.database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False, unique=False)
    email = db.Column(db.String(50), unique=True)
    username = db.Column(db.Text, unique=True)
    password = db.Column(db.String(1000))
    user_image = db.Column(db.Text(1000), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    posts = relationship('Posts', back_populates='username')


class Posts(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, ForeignKey('users.id'), primary_key=True)
    username = relationship('Users', back_populates='posts')
    text = db.Column(db.Integer, nullable=True)
    image = db.Column(db.Text, nullable=False)


db.create_all()






@app.route('/')
def home():
    return render_template('index.html')


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
                return redirect(url_for('home'))
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
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        verify_email = Users.query.filter_by(email=email).first()
        if verify_email in all_users:
            error = 'This email address is already in use'
            return redirect(url_for('login', error=error))
        verify_username = Users.query.filter_by(username=username).first()
        if verify_username in all_users:
            error = 'This username is already taken. Try another one'
            return redirect(url_for('signup', error=error))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = Users(name=name, email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', error=error)


if __name__ == '__main__':
    app.run(debug=True)