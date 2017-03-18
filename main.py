
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









    

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user ##################################################







###Blog Area########################################




#keeps line separatated when typing in new blog with spacing 
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts, deleted_post_id=deleted_post_id)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")
        
        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        if not post:
            self.error(404)
            return
            #NOL = number of likes

        error = self.request.get('error')
        self.render("permalink.html", post = post, NOL = likes.count(),
                     comments = comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""

        if(self.user):
            # clicking like will make post-like value increases.
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                time.sleep(0.01)
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your own" +
                                  "post.!!")
                    return
                
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()
            
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=You need to login before " +
                          "performing edit, like or commenting.!!")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post,
                    comments=comments, NOL=likes.count(),
                    new=c)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), user_id=self.user.key().id(),
            subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                time.sleep(0.1)
                self.redirect("/blog/")
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this record.")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")

class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/login?error=You need to be logged in , in order to " +
                          "delete your comment!!")

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/login?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, post_id, comment_id):
        
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user and self.user.key().id() == post.user_id:
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged in, " +
                          "in order to edit your post!!")
    def post(self, post_id):
        
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            post.subject = subject
            post.content = content

            post.put()

            self.redirect('/blog/%s' % post_id)

        else:
            error = "subject and content needs to be entered!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

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

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
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
    

