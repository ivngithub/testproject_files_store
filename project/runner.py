import click

from flask_script import Manager, Shell
from flask_migrate import MigrateCommand

from app import app, db
from app.models import User, File

manager = Manager(app)


@app.shell_context_processor
def make_shell_context():
    return dict(app=app, db=db, User=User, File=File)

manager.add_command('shell', Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@app.cli.command('start-project')
def start_project():
    """
    start project start-project >>>db.create_all()
    """
    from app import db
    db.create_all()


@app.cli.command('registration-user')
@click.argument('name')
@click.argument('password')
def registration_user(name, password):
    """
    registration user registration-user - <user_name> <password>
    """
    user = User(username=name)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()


@app.cli.command('fake-files')
@click.argument('count_files')
@click.argument('user_name')
def files_generation(count_files, user_name):
    """
    file generation - fake-files <count_files> <user_name>
    """
    import uuid, os, sh
    from fpdf import FPDF

    user = db.session.query(User).filter(User.username == user_name).first_or_404()

    files_store_folder = app.config['FILES_STORE_FOLDER']

    for _ in range(int(count_files)):
        hsh = uuid.uuid4().hex
        file_name = hsh + '.pdf'
        sub_folder_name = hsh[0:2]
        sub_folder = os.path.join(files_store_folder, sub_folder_name)
        if not os.path.exists(sub_folder):
            os.mkdir(sub_folder)

        path_to_file = '{folder}/{name}'.format(folder=sub_folder, name=file_name)
        print(path_to_file)

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt='file name: {name}'.format(name=file_name), ln=1, align="C")
        pdf.output(path_to_file)

        file = File(original_name=file_name, hash=hsh, user_id=user.id, path=path_to_file,
                    total_size=os.path.getsize(path_to_file))

        db.session.add(file)
        db.session.commit()


if __name__ == '__main__':
    manager.run()
