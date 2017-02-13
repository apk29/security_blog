
import os
import jinja2
import webapp2
import hashlib
import hmac
from google.appengine.ext import ndb
SECRET = 'imsosecret'
#template loading code, locations of the templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

#match security
def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

#takes template name and dictionary of parameters to substitue into the template       
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class BlogHandler(webapp2.RequestHandler):
	#code to automatically write on type self.response.out.write
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	#takes template name and dictionary of parameters to substitue into the template       
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	# render calls out wwrite and render_str to print out the template
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.response.headers['Content-Type'] = 'text/plain'
      visits = 0
      visit_cookie_str = self.request.cookies.get('visits')
      if visit_cookie_str:
      	cookie_val = check_secure_val(visit_cookie_str)
      	if cookie_val:
      		visits = int(cookie_val)
      
      visits += 1

      new_cookie_val = make_secure_val(str(visits))

      self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)

      if visits > 10000:
      	self.write("You are the best ever!")
      else: 
      	self.write("You've been here %s times!" % visits)

      
###Blog Area

def blog_key(name = 'default'):
	return ndb.Key('blogs', name)

#This creates the entities the database within the datastore
class Post(ndb.Model):
	subject = ndb.StringProperty(required = True)
	content = ndb.TextProperty(required = True)
	created = ndb.DateTimeProperty(auto_now_add = True)
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
		
class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key.integer_id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
							   ('/blog/?',BlogFront), 
							   ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ],
							   debug=True)		

