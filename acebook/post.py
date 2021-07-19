from acebook.db import get_db

class Post():

  @classmethod
  def create(cls, title, body, user_id):
    db = get_db()
    db.execute(
      'INSERT INTO post (title, body, author_id)'
      ' VALUES (?, ?, ?)',
      (title, body, user_id)
    )
    db.commit()

  @classmethod
  def all(cls):
    db = get_db()
    posts = db.execute(
      'SELECT p.id, title, body, created, author_id, username'
      ' FROM post p JOIN user u ON p.author_id = u.id'
      ' ORDER BY created DESC'
    ).fetchall()

    return [
      Post(
        post['title'],
        post['body'],
        post['id'],
        post['created'],
        post['author_id'],
        post['username']
      ) for post in posts
    ]

  @classmethod
  def find_by_id(cls, id):
    post = get_db().execute(
      'SELECT p.id, title, body, created, author_id, username'
      ' FROM post p JOIN user u ON p.author_id = u.id'
      ' WHERE p.id = ?',
      (id,)
    ).fetchone()

    return Post(
      post['title'],
      post['body'],
      post['id'],
      post['created'],
      post['author_id'],
      post['username']
    )

  def __init__(self, title, body, id, created, author_id, username):
    self.title = title
    self.body = body
    self.id = id
    self.created = created
    self.author_id = author_id
    self.username = username

  def update(self, title, body, id):
    db = get_db()
    db.execute(
      'UPDATE post SET title = ?, body = ?'
      ' WHERE id = ?',
      (title, body, id)
    )
    db.commit()

  def delete(self):
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ?', (self.id,))
    db.commit()
