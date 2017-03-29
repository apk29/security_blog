from google.appengine.ext import db
from helpers import *

#This creates the attributes within the datastore
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    def gertUserName(self):
        user = User.by_id(self.user_id)
        return user.name

        #keeps line separatated when typing in new blog with spacing 
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
