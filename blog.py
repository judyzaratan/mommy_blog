import webapp2
import jinja2
import os
import hashlib
import hmac
import re
import random

import string
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#SECRET

SECRET = 'Imthesecret'

## Salting functions
def make_salt():
    """Creates random five-letter string for salt"""
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    hashed_pw = hashlib.sha256(name + pw + salt).hexdigest()
    return  '%s,%s' % (salt, hashed_pw)

def valid_pw(name, password, hashed_pw):
    salt = hashed_pw.split(',')[0]
    return hashed_pw == make_pw_hash(name, password, salt)

## Hashing cookies

def make_secure_val(val):

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

# Database
#Users
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

#Comments
class Comments(db.Model):
    user = db.ReferenceProperty(User)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#Likes
class Likes(db.Model):
    user = db.ReferenceProperty(User)

# Request handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Routes
class MainPage(Handler):
    def get(self):
        self.render('welcome.html')

class BlogHandler(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * from Post ORDER BY created desc")
        print posts
        self.render("blog.html", posts = posts)

class PostHandler(Handler):
    def get(self, blog_id):
        blog_post = Post.get_by_id(int(blog_id))
        print blog_post.subject
        self.render("post.html", blog_post = blog_post)

class SignupHandler(Handler):
    def get(self):
        user = self.request.cookies.get('username')
        print user
        if(user == "" or user == None):
            self.render('signup.html')
        else:
            self.redirect("/blog/welcome")

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
            assign_cookie = make_secure_val(k.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % assign_cookie + '; Path:/blog')
            self.redirect("/blog/welcome")
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
        password_check = valid_pw(user_name, user_password, database_query.password)
        print "password check" + str(password_check)


        if (database_query) and  (user_name == database_query.user and password_check):
            self.response.headers['Content-Type'] = "text/plain"
            username = str(user_name)
            assign_cookie = make_secure_val(database_query.key().id())
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % assign_cookie + '; Path:/blog')
            self.redirect("/blog/welcome")
        else:
            error_msg = "Invalid credentials"
            self.render("login.html", error_msg = error_msg)

class WelcomeHandler(Handler):
    def get(self):
        print "welcome handler"
        cookie = self.request.cookies.get("user_id")
        id_check = check_secure_val(cookie)
        if id_check:
            username = User.get_by_id(int(id_check)).user
            self.render("welcome.html", username = username)

class NewPostHandler(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newPost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            b = Post(subject = subject, content = content)
            k = b.put()
            index = k.id()
            link = "/blog/" + str(index)
            self.redirect(link)
        else:
            error = "We both need a subject and a post"
            self.render_newpost(subject=subject, content=content, error=error)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/blog')
        self.redirect('/blog/signup')

app = webapp2.WSGIApplication([('/blog', BlogHandler),
                                ('/blog/welcome', WelcomeHandler),
                                ('/blog/login', LoginHandler),
                                ('/blog/(\d+)', PostHandler),
                                ('/blog/signup', SignupHandler),
                                ('/blog/logout', LogoutHandler),
                                ('/blog/newpost', NewPostHandler)], debug=True)
