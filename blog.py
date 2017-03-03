import webapp2
import jinja2
import os
import hashlib
import hmac
import re
import random
import urllib

import string
from google.appengine.ext import db

#SECRET for securing cookies
SECRET = 'Imthesecret'

### JINJA
# Specifies path directory for html templates for jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Jinja templating environment
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Returns rendered template with dictionary input params
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

### Salting functions
def make_salt():
    """
    Creates random five-letter string for salt
    """
    return ''.join(random.choice(string.letters) for x in xrange(5))

    ##xrange function is the same as range but returns an xrange object that
    ## uses same amount of memory regardless of size

def make_pw_hash(name, pw, salt = None):
    """
    Hashes password
    """
    if not salt:
        salt = make_salt()
    hashed_pw = hashlib.sha256(name + pw + salt).hexdigest()
    return  '%s,%s' % (salt, hashed_pw)

def valid_pw(name, password, hashed_pw):
        # Obtain salt
    salt = hashed_pw.split(',')[0]
    return hashed_pw == make_pw_hash(name, password, salt)

## Securing cookies
def make_secure_val(val):
    """Uses database id to create a cookie hash"""
    cookie_h = hmac.new(SECRET, str(val)).hexdigest()
    return '%s|%s' %(val, cookie_h)

def check_secure_val(cookie_h):
    cookie = cookie_h.split('|')[0]
    if make_secure_val(cookie) == cookie_h:
        return cookie

#Regular expressions to check for usernamde, password, and email validity
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

#Validity checks on user inputs
def valid_username(username):
    return USER_RE.match(username)
def valid_password(password):
    return PASSWORD_RE.match(password)
def valid_email(email):
    return EMAIL_RE.match(email)

# Datastore definitions
#User
class User(db.Model):
    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

#Post
class Post(db.Model):
    subject = db.StringProperty(required = True)
    user = db.ReferenceProperty(User)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    """ Renders individual post using post template"""
    def render(self):
        likes = Likes.all().ancestor(self.key()).count()
        return render_str("post.html", blog_post = self, likes = likes)

    def is_liked(self, user):
        u = Likes.all().ancestor(self.key()).filter('user =', user).count()
        print "user function"
        print user
        return u




#Comment
class Comment(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    """ Renders individual comment using comment template"""
    def render(self):
        return render_str("comment.html", comment = self)

#Likes
class Likes(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)


# Request handler
"""Initialize handler instance with req and res objects"""
"""Adds user object in response"""
class Handler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        print 'Initialized'
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        pid = self.request.get("post_id")
        self.post_id = pid
        self.user = uid and User.get_by_id(int(uid))

    """Sets cookie in response header"""
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    """Validates cookie read in response header"""
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    """Simplifies write function"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    """Render dictionary parameters on templates as text"""
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    """Writes rendered template to response"""
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class DeletePostHandler(Handler):
    def post(self):
        post_id = self.request.get('post_id')
        db.delete(Post.get_by_id(int(post_id)))
        self.render("deletedPost.html")


#Page displays blog posts
class BlogHandler(Handler):
    def get(self):
        posts = db.Query(Post).order('-created')
        inputs = {  "posts": posts,
                    "user":self.user,
                    "comment": False,
                    "show_comment":True,
                    "show_like":True    }

        #Removes comment and like button if a user is not logged in
        if not(self.user):
            inputs["show_comment"] = False
            inputs["show_like"] = False

        self.render("blog.html", **inputs)


#Single post display
class PostHandler(Handler):
    def get(self, blog_id):
        post_key = db.Key.from_path('Post', int(blog_id))
        post = db.get(post_key)
        if not post:
            self.error(404)
            return
        comments = Comment.all()
        comments_in_post = comments.filter('post =', post)
        inputs = {  "entry": post,
                    "comments_in_post": comments_in_post,
                    "show_comment": True,
                    "show_like": True   }
        self.render("permalink.html", **inputs)



#Signup
class SignupHandler(Handler):
    def get(self):
        if not self.user:
            self.render('signup.html')
        else:
            self.redirect("/welcome")

    def post(self):
        #User inputs
        have_error = False
        user_name = self.request.get("username")
        user_password = self.request.get("password")
        user_verify = self.request.get("verify")
        user_email = self.request.get("email")

        params = dict(username = user_name,
                      email = user_email)

        #Validity checks
        if not valid_username(user_name):
            params['error_username'] = "That is not a valid username."
            have_error = True

        if not valid_password(user_password):
            params['error_password'] = "That is not a valid password."
            have_error = True
        elif user_password != user_verify:
            params['error_verify'] = "Your passwords do not match."
            have_error = True

        if not valid_email(user_email) and not user_email == "":
            params['error_email'] = "That is not a valid email."
            have_error = True

        # Database
        # Check if user exists
        username_check = User.all().filter('user =', user_name).get()
        if username_check:
            params["error_username"] = "Username already exists"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            hash_pw = make_pw_hash(user_name, user_password)

            u = User(user = user_name, password = hash_pw, email = user_email)
            k = u.put()

            self.response.headers['Content-Type'] = "text/plain"
            username = str(user_name)
            assign_cookie = make_secure_val(u.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % assign_cookie + '; Path:/')
            self.redirect("/welcome")

class LoginHandler(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        user_name = self.request.get("username")
        user_password = self.request.get("password")

        database_query = User.all().filter('user =', user_name).get()
        if database_query:
            password_check = valid_pw(user_name, user_password, database_query.password)

        if (database_query) and  (user_name == database_query.user and password_check):
            self.response.headers['Content-Type'] = "text/plain"
            username = str(user_name)
            assign_cookie = make_secure_val(database_query.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % assign_cookie + '; Path:/')
            self.redirect("/welcome")
        else:
            error_msg = "Invalid credentials"
            self.render("login.html", error_msg = error_msg)

class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            username = self.user.user
            self.render("welcome.html", username = username)
        else:
            self.redirect("/login")

class EditPostHandler(Handler):
    def render_newpost(self, subject="", content="", error="", edittype="New"):
        self.render("newPost.html", subject=subject, content=content, error=error, edittype=edittype)

    def get(self):
        if self.user and self.post_id:
            post_key = db.Key.from_path('Post', int(self.post_id))
            post = db.get(post_key)
            self.render_newpost(subject=post.subject, content=post.content, edittype="Edit")
        elif self.user:
            self.render_newpost()
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/login")

        subject = self.request.get("subject")
        content = self.request.get("content")
        user = self.user
        post = self.post_id

        if not subject or not content:
            error = "We both need a subject and a post"
            self.render_newpost(subject=subject, content=content, error=error)
        else:
            if post:
                """Updates existing post in database"""
                post = Post.get_by_id(int(self.post_id))
                post.subject = subject
                post.content = content
            else:
                """Adds new post in database"""
                post = Post(subject = subject, content=content, user=user)
            k = post.put()
            index = k.id()
            link = "/" + str(index)
            self.redirect(link)


class CommentHandler(Handler):
    def get(self):
        comment_id = self.request.get("comment_id")
        post_id = self.request.get("post_id")
        if self.user and self.request.get("comment_id"):
            post = Post.get_by_id(int(post_id))
            editcomment= Comment.get_by_id(int(comment_id), parent=post)
            self.render('newComment.html', comment_text = editcomment.content, post_id=post_id)
            # self.render(comment_text=comment.content)
        elif self.user:
            self.render("newComment.html", post_id=post_id)
        else:
            self.redirect('/')


    def post(self):
        path = self.request.get('button')
        comment = self.request.get('comment')
        p=self.request.get('post_id')
        post_id = Post.get_by_id(int(p))
        user = self.user
        if path == "Submit":
            o = Comment(parent=post_id, user = user, content = comment, post = post_id)
            k = o.put()
            self.redirect('/')

        if path == "Cancel":
            link = '/' + p
            self.redirect(link)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/signup')

class LikesHandler(Handler):
    def post(self):
        post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id))
        l = Likes(parent = post, user=self.user, post=post)
        e = l.put()
        print "uri"
        print self.request.uri
        self.redirect("/")

class UnlikeHandler(Handler):
    def post(self):
        post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id))
        l = Likes.all().filter('post =', post).filter('user =', self.user)
        print l.count()
        for likes in l:
            likes.delete()
        self.redirect('/')

app = webapp2.WSGIApplication([('/', BlogHandler),
                                ('/welcome', WelcomeHandler),
                                ('/signup', SignupHandler),
                                ('/login', LoginHandler),
                                ('/likes', LikesHandler),
                                ('/logout', LogoutHandler),
                                ('/(\d+)', PostHandler),
                                ('/newpost', EditPostHandler),
                                ('/deletepost', DeletePostHandler),
                                ('/newcomment', CommentHandler),
                                ('/unlike', UnlikeHandler)], debug=True)
