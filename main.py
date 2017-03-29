
import os
import re
import random
import jinja2
import webapp2
import hashlib
import hmac
import time

from string import letters
from google.appengine.ext import db

#model
from models.comment import Comment
from models.user import User
from models.post import Post
from models.like import Like

#handlers
from handlers.blog import BlogHandler
from handlers.signup import Signup
from handlers.blogfront import BlogFront
from handlers.deletecomment import DeleteComment
from handlers.post import PostPage
from handlers.newpost import NewPost
from handlers.login import Login
from handlers.logout import Logout
from handlers.deletepost import DeletePost
from handlers.editpost import EditPost
from handlers.editcomment import EditComment

  
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'This is an existing user.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ],
                              debug=True)
    

