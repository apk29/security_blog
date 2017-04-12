from google.appengine.ext import db
from handlers.blog import BlogHandler
from helpers import *

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if self.user.key().id() == post.user_id:
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to edit this record.")
        else:
            self.redirect("/login?error=You need to be logged in, " +
                          "in order to edit your post!!")
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            post.subject = subject
            post.content = content

            post.put()

            self.redirect('/blog/%s' % post_id)

        else:
            error = "subject and content needs to be entered!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)