from flask import render_template, request, redirect, url_for, flash, make_response, session, abort
from flask_login import login_required, login_user,current_user, logout_user

from app import app
from .models import db, User, File
from .forms import LoginForm


@app.route('/login/', methods=['post', 'get'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))

        flash("Invalid username/password", 'error')
        return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))


@app.route('/')
# @login_required
def index():
    return render_template('index.html')


@app.route('/files-list/', methods=['GET', 'POST'])
# @login_required
def files_list():
    page = request.args.get('page', 1, type=int)
    per_page = app.config['FILES_PER_PAGE']

    # files = db.session.query(File).limit(per_page).offset((page - 1) * per_page).all()

    files = File.query.paginate(page, per_page, False)

    next_url = url_for('files_list', page=files.next_num) if files.has_next else None
    prev_url = url_for('files_list', page=files.prev_num) if files.has_prev else None

    return render_template('files_list.html', files=files.items, next_url=next_url, prev_url=prev_url)


@app.route('/file-card/<hash_id>')
# @login_required
def file_card(hash_id):
    file = db.session.query(File).filter(File.hash == hash_id).first_or_404()

    return render_template('file_card.html', file=file)

@app.route('/file-upload/')
# @login_required
def file_upload():
    return render_template('file_upload.html')


@app.errorhandler(404)
def http_404_handler(error):
    return "<p>HTTP 404 Error Encountered</p>", 404


@app.errorhandler(500)
def http_500_handler(error):
    return "<p>HTTP 500 Error Encountered</p>", 500


@app.route("/error/")
def error():
    abort(404)