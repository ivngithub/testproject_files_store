from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, IntegerField
from wtforms.validators import DataRequired, ValidationError


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Submit")


class SearchForm(FlaskForm):
    file_name = StringField("File name")
    size_from = IntegerField("Size from")
    size_to = IntegerField("Size to")
    submit = SubmitField("Submit")

    def validate_size_from(self, size_from):

        if size_from.data is None or self.size_to.data is None or size_from.data > self.size_to.data:
            raise ValidationError('Size from must be more than size to')