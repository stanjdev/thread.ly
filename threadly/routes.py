from unicodedata import name
from flask import Blueprint, request, render_template, redirect, url_for, flash
from datetime import date, datetime
from flask_bcrypt import Bcrypt

from flask_login import login_required, login_user, logout_user, current_user
from threadly.models import Thread, Comment, User
from threadly.forms import ThreadForm, CommentForm, LoginForm, SignUpForm

# Import app and db from events_app package so that we can run app
from threadly.extensions import app, db

bcrypt = Bcrypt(app)
main = Blueprint("main", __name__)

##########################################
#                Routes                  #
##########################################

@main.route('/')
def homepage():
    all_threads = Thread.query.all()
    print(current_user)
    return render_template('home.html', all_threads=all_threads, current_user=current_user)

@main.route('/new_thread', methods=['GET', 'POST'])
@login_required
def new_thread():
    # Create a Thread
    form = ThreadForm()
    # If form was submitted and was valid:
    if request.method == 'POST':
        thread_topic = request.form.get('topic')
        thread_description = request.form.get('description')
        thread_image_url = request.form.get('image_url')

        existing_thread = Thread.query.filter_by(topic=thread_topic).first()
        if existing_thread is None:
            # - create a new Thread object and save it to the database
            thread = Thread(
                topic = thread_topic,
                description = thread_description,
                image_url = thread_image_url,
                created_by = current_user,
            )
            db.session.add(thread)
            db.session.commit()
            # - flash a success message
            flash('New thread created!')
            # - redirect the user to the thread detail page.
            return redirect(url_for('main.thread_detail', thread_id=thread.id))
        else:
            flash(f'"{thread_topic}" thread already exists. Topic must be unique.')
            return render_template('new_thread.html', form=form)
    else:
        # Send the form to the template and use it to render the form fields
        return render_template('new_thread.html', form=form)

@main.route('/thread/<thread_id>', methods=['GET', 'POST'])
@login_required
def thread_detail(thread_id):
    thread = Thread.query.get(thread_id)
    # Create a ThreadForm and pass in `obj=thread`
    form = ThreadForm(obj=thread)
    comment_form = CommentForm()
    thread_author = thread.created_by
    # If form was submitted and was valid:
    if request.method == 'POST':
    # - update the Thread object and save it to the database,
        thread.description = request.form.get('description')
        thread.image_url = request.form.get('image_url')
        db.session.commit()
    # - flash a success message, and
        flash('Thread was updated.')
        # - redirect the user to the thread detail page.
        return redirect(url_for('main.thread_detail', thread_id = thread.id))
    # Send the form to the template and use it to render the form fields
    else:
        return render_template('thread_detail.html', thread=thread, thread_author=thread_author, form=form, comment_form=comment_form, current_user=current_user)

@main.route('/user_threads')
@login_required
def user_threads():
    threads = current_user.threads
    return render_template('user_threads.html', threads=threads, current_user=current_user)

@main.route('/thread/<thread_id>/comments', methods=['GET', 'POST'])
@login_required
def new_comment(thread_id):
    this_thread = Thread.query.get(thread_id)
    # If form was submitted and was valid:
    if request.method == 'POST':
        comment_content = request.form.get('content')

    # - create a new Comment object and save it to the database,
        comment = Comment(
            content = comment_content,
            thread_id = thread_id,
            created_by = current_user,
        )
        db.session.add(comment)
        db.session.commit()

        # - flash a success message, and
        flash('Comment created.')
        # - redirect the user to the thread detail page.
        return redirect(url_for('main.thread_detail', thread_id=this_thread.id))
    else: 
        # Send the form to the template and use it to render the form fields
        return redirect(url_for('main.thread_detail', thread_id=this_thread.id))

@main.route('/thread/<thread_id>/comments/<comment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(thread_id, comment_id):
    this_thread = Thread.query.get(thread_id)
    comment = Comment.query.get(comment_id)
    comment_form = CommentForm(obj=comment)
    # If form was submitted and was valid:
    if request.method == 'POST':
        comment_content = request.form.get('content')
    # - Update Comment object and save it to the database,
        comment.content = comment_content
        db.session.commit()
        # - flash a success message, and
        flash('Comment Updated.')
        # - redirect the user to the thread detail page.
        return redirect(url_for('main.thread_detail', thread_id=this_thread.id))
    else: 
        # Send the form to the template and use it to render the form fields
        return render_template('comment_edit.html', comment_form=comment_form, comment=comment, thread=this_thread)

@main.route('/thread/<thread_id>/comments/<comment_id>/delete', methods=['GET'])
@login_required
def delete_comment(thread_id, comment_id):
    this_thread = Thread.query.get(thread_id)
    comment = Comment.query.filter_by(id=comment_id)
    comment.delete()
    db.session.commit()
    flash('Comment Deleted.')
    return redirect(url_for('main.thread_detail', thread_id=this_thread.id))


##########################################
#            AUTHENTICATION              #
##########################################

auth = Blueprint("auth", __name__)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    print('in signup')
    form = SignUpForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username = form.username.data,
            password = hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        flash('Account Created! Please log in')
        print('created')
        return redirect(url_for('auth.login'))
    print(form.errors)
    return render_template('signup.html', form=form)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        found_user = User.query.filter_by(username=form.username.data).first()
        login_user(found_user, remember=True)
        next_page = request.args.get('next')
        # - flash a success message
        flash(f'Welcome {found_user.username}!')
        return redirect(next_page if next_page else url_for('main.homepage'))
    return render_template('login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Goodbye!')
    return redirect(url_for('main.homepage'))
