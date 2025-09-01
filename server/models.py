from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String, default="https://via.placeholder.com/150")
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", back_populates="user", cascade="all, delete-orphan")

    serialize_rules = ("-recipes.user", "-_password_hash")

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        if password:
            password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
            self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == "":
            raise ValueError("Username must be present")
        
        # Check for uniqueness, excluding current instance if it exists
        existing_user = User.query.filter(User.username == username).first()
        if existing_user and existing_user.id != self.id:
            raise ValueError("Username must be unique")
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = db.relationship("User", back_populates="recipes")

    serialize_rules = ("-user.recipes",)

    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == "":
            raise ValueError("Title must be present")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or instructions.strip() == "":
            raise ValueError("Instructions must be present")
        if len(instructions.strip()) < 50:
            raise ValueError("Instructions must be at least 50 characters long")
        return instructions

    @validates('minutes_to_complete')
    def validate_minutes_to_complete(self, key, minutes):
        if minutes is None or minutes < 1:
            raise ValueError("Minutes to complete must be a positive integer")
        return minutes

    @validates('user_id')
    def validate_user_id(self, key, user_id):
        if user_id is None:
            raise ValueError("Recipe must be associated with a user")
        return user_id