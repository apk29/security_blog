from google.appengine.ext import db
from handlers.blog import BlogHandler
from helpers import *
from models.comment import Comment

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
                                  " post.!!")
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
                time.sleep(0.01)
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