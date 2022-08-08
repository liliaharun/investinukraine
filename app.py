from flask import Flask, render_template, request, redirect, flash, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import smtplib
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
ckeditor = CKEditor(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://ueqwhyitdqpald:a92bd46e285ca229e7aeb0a2a7a82c402d623f18fe4d8f7a3796f062a13a844f@ec2-44-193-178-122.compute-1.amazonaws.com:5432/df7sn36f21ef10'

app.config['SECRET_KEY'] = "my secret key"


#Initialize the database
db = SQLAlchemy(app)

migrate = Migrate(app, db)

#create blog model
class Blogs(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    author = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

#create a blogs form
class BlogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    submit = SubmitField('Submit')

#flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view ='login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#create LoginForm
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


#login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
        #check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password. Please try again')
        else:
            flash ("That user doesn't exist")

    return render_template('login.html', form=form)


#dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/blogs')
def blogs():

    blogs = Blogs.query.order_by(Blogs.date_posted)
    return render_template("blogs.html", blogs=blogs)

@app.route('/blogs/delete/<int:id>')
def delete_blog(id):
    blog_delete = Blogs.query.get_or_404(id)
    try:
        db.session.delete(blog_delete)
        db.session.commit()

        flash("Project was deleted!")
        blogs = Blogs.query.order_by(Blogs.date_posted)
        return render_template("blogs.html", blogs=blogs)
    except:
        flash("There was a problem deleting the project. Please try again!")
        blogs = Blogs.query.order_by(Blogs.date_posted)
        return render_template("blogs.html", blogs=blogs)

#logout page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))

# add Blog page
@app.route('/add-blog', methods=['GET', 'POST'])
@login_required
def add_blog():
    form = BlogForm()

    if form.validate_on_submit():
        blog = Blogs(title=form.title.data, content=form.content.data, author=form.author.data, 
        #slug=form.slug.data
        )
        form.title.data = ''
        form.content.data=''
        form.author.data = ''

        #add blog data to db
        db.session.add(blog)
        db.session.commit()

        flash('Project Post submitted!')
        #redirect to blogs page
        return redirect(url_for('blog', id=blog.id))

    #redirect to add blog page
    return render_template('add_blog.html', form=form)

@app.route('/blogs/<int:id>')
def blog(id):
    blog = Blogs.query.get_or_404(id)
    return render_template("blog.html", blog=blog)

@app.route('/blogs/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_blog(id):
    blog = Blogs.query.get_or_404(id)
    form = BlogForm()
    if form.validate_on_submit():
        blog.title = form.title.data
        blog.author = form.author.data
        blog.content = form.content.data
        #update Db
        db.session.add(blog)
        db.session.commit()

        flash('Project has been updated!')

        #redirect to blogs page
        return redirect(url_for('blog', id=blog.id))
    form.title.data = blog.title
    form.author.data = blog.author
    form.content.data = blog.content
    return render_template('edit_blog.html', form = form)



#Create db model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    #create hashing passwords
    password_hash = db.Column(db.String(120))
    username = db.Column(db.String(200), nullable=False, unique = True)

    @property
    def password(self):
        raise AttributeError("password is not readable attribute!")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


    #create a function to return a string when we add sth
    def __repr__(self):
        return '<Name %r>' % self.name
#delete user
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get(id)
    name = None
    form = UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit ()
        flash("User deleted")
            
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', name = name, form = form, our_users=our_users)

    except:
        flash("There was a problem deleting")
        return render_template('add_user.html', name = name, form = form, our_users=our_users)




#Create a Form Class
class UserForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Submit")
    username=StringField("Username", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match!')])
    password_hash2 = PasswordField('Confirm Password',validators=[DataRequired()] )

#update database record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404 (id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
       
        try:
            db.session.commit()
            flash('User updated successfully!')
            return render_template ('update.html', form=form, name_to_update=name_to_update)
        except:
            flash('Error! Looks like there was a problem...')

            return render_template ('update.html', form=form, name_to_update=name_to_update)
    else:
        return render_template ('update.html', form=form, name_to_update=name_to_update)

subscribers = []

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    
    #Validate Form
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name = form.name.data, email = form.email.data, username=form.username.data, password_hash=hashed)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.username.data = ''
        form.password_hash = ''
        flash("User Added Successfully!")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', name = name, form = form, our_users=our_users)


@app.route('/contact')
def contact():
	title = "Contact Us"
	return render_template ("contact.html", title = title)

@app.route('/')
def index():
	title = "Invest In Ukraine"
	return render_template ("index.html", title = title)

@app.route('/about')
def about():
    title = "About Us"
    return render_template('about.html', title = title)

@app.route('/subscribe')
def subscribe():
	title = "Subscribe To Our Email Newsletter"
	return render_template ("subscribe.html", title = title)

@app.route('/form', methods =["POST"])
def form():
    first_name = request.form.get("first_name")
    last_name = request.form.get("last_name")
    email = request.form.get("email")
    
    message = "You have been subscibed to our email newsletter"
    server = smtplib.SMTP("smtp.ukr.net", 465)
    server.starttls()
    server.login("liliasinbox@ukr.net", "t358pA333ydVtUdG")
    server.sendmail("liliasinbox@ukr.net", email, message)
    
    if not first_name or not last_name or not email:
        apology = "All Form Fields required.."
        return render_template ("subscribe.html", 
            apology = apology, 
            first_name = first_name, 
            last_name = last_name, 
            email = email)
        
    
    subscribers.append(f"{first_name} {last_name} | {email}")
    title = "Thank You"
    return render_template ("form.html", title = title, subscribers=subscribers)