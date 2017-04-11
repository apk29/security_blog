from google.appengine.ext import db
from handlers.blog import BlogHandler
from helpers import *

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.redirect("/blog/")
                return
            
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