import os, logging

from flask import render_template, request, redirect, url_for, flash, abort, send_file, after_this_request,\
    make_response
from werkzeug.utils import secure_filename
from flask_login import login_required, login_user,current_user, logout_user

from app import app
from .models import db, User, File, FileAccess
from .forms import LoginForm


logging.basicConfig(filename="pydrop.log", level=logging.INFO)
log = logging.getLogger('pydrop')


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


@app.route('/download/<file_hash>')
# @login_required
def download(file_hash):
    file = db.session.query(File).filter(File.hash == file_hash).first_or_404()
    path_to_file = file.path

    @after_this_request
    def lock_access(response):
        access = FileAccess(file_id=file.id, user_id=current_user.id)
        db.session.add(access)
        db.session.commit()

        return response

    # #FIXME rattle - if you have very more clicks on download button. it's problem.
    # access = FileAccess(file_id=file.id, user_id=current_user.id)
    # db.session.add(access)
    # db.session.commit()

    return send_file(path_to_file, as_attachment=True, cache_timeout=0)


@app.route('/file-card/<hash_id>')
# @login_required
def file_card(hash_id):
    file = db.session.query(File).filter(File.hash == hash_id).first_or_404()

    return render_template('file_card.html', file=file)

@app.route('/file-upload/')
# @login_required
def file_upload():
    return render_template('file_upload.html')


@app.route('/upload', methods=['POST'])
# @login_required
def upload():
    # # Route to deal with the uploaded chunks
    # log.info(request.form)
    # log.info(request.files)
    file = request.files['file']

    save_path = os.path.join(app.config['FILES_STORE_FOLDER'], secure_filename(file.filename))
    current_chunk = int(request.form['dzchunkindex'])

    # If the file already exists it's ok if we are appending to it,
    # but not if it's new file that would overwrite the existing one
    if os.path.exists(save_path) and current_chunk == 0:
        # 400 and 500s will tell dropzone that an error occurred and show an error
        return make_response(('File already exists', 400))

    try:
        with open(save_path, 'ab') as f:
            f.seek(int(request.form['dzchunkbyteoffset']))
            f.write(file.stream.read())
    except OSError:
        # log.exception will include the traceback so we can see what's wrong
        log.exception('Could not write to file')
        return make_response(("Not sure why, but we couldn't write the file to disk", 500))

    total_chunks = int(request.form['dztotalchunkcount'])

    if current_chunk + 1 == total_chunks:
        # This was the last chunk, the file should be complete and the size we expect
        if os.path.getsize(save_path) != int(request.form['dztotalfilesize']):
            log.error("File {} was completed, but has a size mismatch. "
                      "Was {} but we expected {} "
                      .format(file.filename, os.path.getsize(save_path), request.form['dztotalfilesize']))
            return make_response(('Size mismatch', 500))
        else:
            log.info('File {} has been uploaded successfully'.format(file.filename))
    else:
        log.debug('Chunk {} of {} for file {} complete'.format(current_chunk + 1, total_chunks, file.filename))

    return make_response(('Chunk upload successful', 200))


@app.errorhandler(404)
def http_404_handler(error):
    return "<p>HTTP 404 Error Encountered</p>", 404


@app.errorhandler(500)
def http_500_handler(error):
    return "<p>HTTP 500 Error Encountered</p>", 500


@app.route("/error/")
def error():
    abort(404)
