from flask import Blueprint, render_template, request, flash, redirect, url_for , make_response
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import pdfkit





auth = Blueprint('auth', __name__)

@auth.route('/', methods=['GET', 'POST'])
def register():
    post_id = request.form.get('register')
    if request.method == 'POST':
        if post_id is not None:
            email = request.form.get('email')
            name = request.form.get('name')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')

            
            if User.query.filter_by(email=email).first():
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif len(name) < 2:
                flash('First name must be greater than 1 character.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
            else:
                new_user = User(email=email, name=name, password=generate_password_hash(
                    password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.user'))
    

        else:
            email = request.form.get('email')
            password = request.form.get('password')

            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.user'))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')

    return render_template("Home.html", user=current_user)
       
@auth.route('/about')
def about():
   return render_template('about.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.register'))

@auth.route('/template1', methods=['GET', 'POST'])
def temp1():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        address = request.form.get('address')
        contect = request.form.get('contect')
        objective = request.form.get('objective')
        year = request.form.get('contect')
        qualification = request.form.get('qualification')
        board = request.form.get('contect')

        if objective =="":
            objective= "Looking for a position where I can use my skills and ability for mutual growth and profit."


        return render_template('resume.html', name=name,address=address,email=email,contect=contect,objective=objective,year=year,qualification=qualification,board=board )





    return render_template('temp1.html')




@auth.route('/download')
def pdf_template():
    render = render_template('resume.html')
    options = {
    'page-size':'A4',
    'encoding':'utf-8', 
    'margin-top':'0cm',
    'margin-bottom':'0cm',
    'margin-left':'0cm',
    'margin-right':'0cm'
    }
    pdf = pdfkit.from_string(render , False ,options=options)
    

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=resume.pdf'
    return response






