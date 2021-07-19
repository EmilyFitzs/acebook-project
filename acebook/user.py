from acebook.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

class User():
  
  @classmethod
  def create(cls, firstname, lastname, birthday, username, password):
    db = get_db()
    db.execute(
      'INSERT INTO user (firstname, lastname, birthday, username, password) VALUES (?, ?, ?, ?, ?)',
      (firstname, lastname, birthday, username, generate_password_hash(password))
    )
    db.commit()

  @classmethod
  def find(cls, username):
    db = get_db()
    user = db.execute(
      'SELECT id, firstname, lastname, birthday, username, password FROM user WHERE username = ?', (username,)
    ).fetchone()
    if user:
      return User(user['firstname'], user['lastname'], user['birthday'], user['username'], user['password'], user['id'])
    else:
      return None

  @classmethod
  def find_by_id(cls, user_id):
    user = get_db().execute(
      'SELECT id, firstname, lastname, birthday, username, password FROM user WHERE id = ?', (user_id,)
    ).fetchone()
    if user:
      return User(user['firstname'], user['lastname'], user['birthday'], user['username'], user['password'], user['id'])
    else:
      return None

  def __init__(self, firstname, lastname, birthday, username, password, id):
    self.firstname = firstname
    self.lastname = lastname
    self.birthday = birthday
    self.username = username
    self.password = password
    self.id = id

  def authenticate(self, password):
    return check_password_hash(self.password, password)
