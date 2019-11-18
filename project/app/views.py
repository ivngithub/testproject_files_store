import os, logging, uuid

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
    # need for debug
    # # Route to deal with the uploaded chunks
    # log.info(request.form)
    # log.info(request.files)

    files_store_folder = app.config['FILES_STORE_FOLDER']
    hsh = request.form['dzuuid']

    file = request.files['file']
    original_filename = file.filename

    # I think keeping all the files in one folder is a bad idea.
    sub_folder_name = hsh[0:2]
    sub_folder = os.path.join(files_store_folder, sub_folder_name)
    if not os.path.exists(sub_folder):
        os.mkdir(sub_folder)

    tmp_path = os.path.join(sub_folder, secure_filename(original_filename))
    _, file_extension = os.path.splitext(tmp_path)
    new_file_name = hsh + file_extension
    path_to_file = '{folder}/{name}'.format(folder=sub_folder, name=new_file_name)

    current_chunk = int(request.form['dzchunkindex'])

    # If the file already exists it's ok if we are appending to it,
    # but not if it's new file that would overwrite the existing one
    if os.path.exists(path_to_file) and current_chunk == 0:
        # 400 and 500s will tell dropzone that an error occurred and show an error
        return make_response(('File already exists', 400))

    try:
        with open(path_to_file, 'ab') as f:
            f.seek(int(request.form['dzchunkbyteoffset']))
            f.write(file.stream.read())
    except OSError:
        # log.exception will include the traceback so we can see what's wrong
        log.exception('Could not write to file')
        return make_response(('Not sure why, but we couldn\'t write the file to disk', 500))

    total_chunks = int(request.form['dztotalchunkcount'])

    if current_chunk + 1 == total_chunks:
        # This was the last chunk, the file should be complete and the size we expect
        if os.path.getsize(path_to_file) != int(request.form['dztotalfilesize']):
            log.error("File {} was completed, but has a size mismatch. "
                      "Was {} but we expected {} "
                      .format(original_filename, os.path.getsize(path_to_file), request.form['dztotalfilesize']))
            return make_response(('Size mismatch', 500))
        else:
            log.info('File {} has been uploaded successfully'.format(original_filename))

            hsh = uuid.uuid4().hex
            new_file = '{folder}/{name}'.format(folder=sub_folder, name=hsh + file_extension)
            os.rename(path_to_file, new_file)

            log.info('File {} has been renamed to {}'.format(original_filename, new_file))

            file = File(original_name=original_filename, hash=hsh, user_id=current_user.id, path=new_file)

            db.session.add(file)
            db.session.commit()

    else:
        log.debug('Chunk {} of {} for file {} complete {}'
                  .format(current_chunk + 1, total_chunks, original_filename, request.form))

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
