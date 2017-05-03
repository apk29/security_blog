from google.appengine.ext import db
from handlers.blog import BlogHandler
from helpers import *
from models.comment import Comment

class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), pareent=blog_key())
		post = db.get(key)

		comments = db.GQLQuery("select * from Comment where ancestor is :1 order \
								by created desc, key")
		if not post:
			self.error(404)
			return
		
		error = self.request.get('error')
		self.render("permalink.html", post=post, comments=comments, error=error)