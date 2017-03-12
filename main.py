
import os
import re
import random
import jinja2
import webapp2
import hashlib
import hmac
import time

from string import letters
from google.appengine.ext import ndb

secret = 'thecatinthehat'
#template loading code, locations of the templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)



def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    #code to automatically write or type self.response.out.write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #takes template name and dictionary of parameters to substitue into the template       
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    # render calls out write and render_str to print out the template
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### user ##################################################

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key('users', group)

#stores user info
class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

#Returns user id from User object
    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent = users_key())

#Fetchs users by name from the User object
    @classmethod
    # def by_name(self, name):
    #   u = User.query().filter(ndb.GenericProperty('name'), name).get()
    #   return u

    #alternative method to the above code
    def by_name(cls, name):
        user = User.query(User.name==name).fetch(1)
        for u in user:
            return u    

#Creates the new user in the User object.
    @classmethod
    def register(self, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

#Login in Method
    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
  
  ###Blog Area########################################

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

#This creates the attributes within the datastore
class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.KeyProperty(kind="User")
    last_modified = ndb.DateTimeProperty(auto_now = True)
    


#keeps line separatated when typing in new blog with spacing  
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
        
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.query().order(-Post.created)
        self.render("front.html", posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return
        self.render('post.html', posts=posts)
    

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
            p = Post(parent = blog_key(), subject = subject, content = content, author = self.user.key)
            p.put()
            self.redirect('/blog/%s' % str(p.key.integer_id()))
        else:
            error = "You need to enter subject and content!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()    

        if self.user:
            if post.author.id() != self.user.key.id():
                self.redirect('/blog/' % str(post.key.id()))
            else:
                self.render('editpost.html', subject=post.subject, 
                            content=post.content)
        else: 
            error='Please login first'
            self.render('login.html',error=error)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()
        userid = self.read_secure_cookie('user_id')
        subject = self.request.get('subject')
        content = self.request.get('post_text')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            time.sleep(0.1)
            self.redirect('/')
        else:
            error = "Please enter Subject and Content"
            self.render("editpost.html",
                        subject=subject,
                        content=content,
                        error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent = blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        if self.user:
            self.render('deletepost.html', post=post)
        else:
            error = "Please login first"
            self.render('login.html', error=error)

    def post(self,post_id):
        if not self.user:
            return self.redirect('/login')
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if post and (post.author.id() == self.user.key.id()):
            post.key.delete()
            time.sleep(0.1)
        self.redirect('/blog')

class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        like_obj = Like.query(Like.post == post.key).get()

        if post.author == self.user.key:
            self.write("You can't like your own post")
        else:
            if like_obj:
                authors = like_obj.author
                for author in authors:
                    if(author == self.user.key):
                        return self.redirect("/blog/%s" % str(post.key.id()))
                like_obj.like_count += 1
                authors.append(self.user.key)
                like_obj.put()
                self.redirect('/')
            else:
                like_obj = Like(post=post.key, like_count=1)
                like_obj.author.append(self.user.key)
                like_obj.put()
                self.redirect('/')


# Unlike Post
class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')
            return

        like_obj = Like.query(Like.post == post.key).get()

        if like_obj:
            authors = like_obj.author
            for author in authors:
                if author == self.user.key:
                    like_obj.author.remove(author)
                    flag = True
                if not flag:
                    self.redirect('/blog/%s' % str(post.key.id()))
                else:
                    self.write("user doesn't exist")
        else:
            self.write("No Like object created")

    

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

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

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            key = u.put()

            self.login(u)
            self.redirect('/unit3/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

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
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/unlike/([0-9]+)', UnlikePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ],
                              debug=True)
    

