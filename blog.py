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
        return render_str("post.html", blog_post = self)

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
    post = db.ReferenceProperty(Post, collection_name="likes_set")

# Request handler
"""Initialize handler instance with req and res objects"""
"""Adds user object in response"""
class Handler(webapp2.RequestHandler):
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
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

    # def post_edit(self):
    #     post_id = self.request.get('post_id')
    #     task = self.request.get('task')
    #     print task
    #     if task == 'comment':
    #         query_params = {'post': post_id}
    #         link = '/newcomment?'
    #         self.redirect(link + urllib.urlencode(query_params))
    #     if task == 'like':
    #         post_id = Post.get_by_id(int(post))
    #         c = Likes(parent = post_id, user = self.user, post = post_id)
    #         c.put()
    #         self.redirect("/")


class DeletePostHandler(Handler):
    def post(self):
        post_id = self.request.get('post_id')
        db.delete(Post.get_by_id(int(post_id)))
        self.render("deletedPost.html")


#Page displays blog posts
class BlogHandler(Handler):
    def get(self):
        print 'it got refreshed'
        user = self.request.get('user_id')
        username = self.read_secure_cookie(user)
        posts = db.Query(Post).order('-created')
        for post in posts:
            print post.key().id()
        print 'posts'
        self.render("blog.html", posts = posts, username = username)



#Single post display
class PostHandler(Handler):
    def get(self, blog_id):
        blog_post = Post.get_by_id(int(blog_id))
        post_key = blog_post.key()
        print str(post_key)
        post = db.get(post_key)
        comments = Comment.all()
        comments_in_post = comments.filter('post =', post)
        self.render("permalink.html", entry = post, comments_in_post = comments_in_post)

    def post(self, blog_id):
        self.post_edit()

#Signup
class SignupHandler(Handler):
    def get(self):
        user = self.request.cookies.get('user_id')
        print user
        if(user == "" or user == None):
            self.render('signup.html')
        else:
            self.redirect("/welcome")

    def post(self):
        #User inputs
        user_name = self.request.get("username")
        user_password = self.request.get("password")
        user_verify = self.request.get("verify")
        user_email = self.request.get("email")

        # Validity checks
        name = valid_username(user_name)
        password = valid_password(user_password)
        if(user_email != ""):
            email = valid_email(user_email)
        else:
            email = True

        # Validity checks
        error_username = ""
        error_password = ""
        error_email = ""

        if (user_password != user_verify):
            error_verify = "Passwords do not match."
        if not name:
            error_username = "That's not a valid username."
        if not password:
            error_password = "That's not a valid password."
        if not email:
            error_email = "That's not a valid email."

        # Database
        #Check if user exists
        username_check = User.all().filter('user =', user_name).get()
        if username_check:
            error_username = "Username already exists"
        else:
            username_check = ""


        if name and password and email and (user_password == user_verify) and not username_check:
            hash_pw = make_pw_hash(user_name, user_password)

            u = User(user = user_name, password = hash_pw, email = user_email)
            k = u.put()

            self.response.headers['Content-Type'] = "text/plain"
            username = str(user_name)
            assign_cookie = make_secure_val(u.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % assign_cookie + '; Path:/')
            self.redirect("/welcome")
        else:
            self.render("signup.html", username = user_name,
                                password = user_password,
                                email = user_email,
                                verify = user_verify,
                                error_email = error_email,
                                error_password = error_password,
                                error_username = error_username)

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
        cookie = self.request.cookies.get("user_id")
        id_check = check_secure_val(cookie)
        print id_check
        if id_check:
            username = User.get_by_id(int(id_check)).user
            self.render("welcome.html", username = username)

class EditPostHandler(Handler):
    def render_newpost(self, subject="", content="", error="", edittype="New"):
        self.render("newPost.html", subject=subject, content=content, error=error, edittype=edittype)

    def get(self):
        if self.user and self.request.get("post_id"):
            post_id = self.request.get("post_id")
            blog_post = Post.get_by_id(int(post_id))
            post_key = blog_post.key()
            print str(post_key)
            post = db.get(post_key)
            self.render_newpost(subject=post.subject, content=post.content, edittype="Edit")

        elif self.user:
            self.render_newpost()
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        post_id = self.request.get("post_id")

        cookie = self.request.cookies.get("user_id")
        id_check = check_secure_val(cookie)
        if id_check:
            user = User.get_by_id(int(id_check))

        if subject and content and post_id:
            post = Post.get_by_id(int(post_id))
            post.subject = subject
            post.content = content
            k = post.put()
            index = k.id()
            link = "/" + str(index)
            self.redirect(link)
        elif subject and content and not post_id:
            b = Post(subject = subject, content=content, user=user)
            k = b.put()
            index = k.id()
            link = "/" + str(index)
            self.redirect(link)
        else:
            error = "We both need a subject and a post"
            self.render_newpost(subject=subject, content=content, error=error)


class CommentHandler(Handler):
    def get(self):
        if self.user:
            self.render("newComment.html")
        else:
            self.redirect("/")

    def post(self):
        path = self.request.get('button')
        comment = self.request.get('comment')
        p = self.request.get('post_id')
        print p + 'comment'
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

app = webapp2.WSGIApplication([('/', BlogHandler),
                                ('/welcome', WelcomeHandler),
                                ('/signup', SignupHandler),
                                ('/login', LoginHandler),
                                ('/logout', LogoutHandler),
                                ('/(\d+)', PostHandler),
                                ('/newpost', EditPostHandler),
                                ('/deletepost', DeletePostHandler),
                                ('/newcomment', CommentHandler)], debug=True)
