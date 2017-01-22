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
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    ###Your code here
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return  '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


## Hashing cookies
def make_secure_val(s):
    hashed_password = hmac.new(SECRET, s).hexdigest()
    return '%s|%s' %(password, hashed_password)

def check_secure_val(h):
    cookie = h.split('|')
    s = cookie[0]
    if make_secure_val(s) == cookie[1]:
        return s

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
#Blog Database
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#Users Database
class Users(db.Model):
    user = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()


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
        posts = db.GqlQuery("SELECT * from Blog ORDER BY created desc")
        print posts
        self.render("blog.html", posts = posts)

class PostHandler(Handler):
    def get(self, blog_id):
        blog_post = Blog.get_by_id(int(blog_id))
        print blog_post.subject
        self.render("post.html", blog_post = blog_post)

class SignupHandler(Handler):
    def get(self):
        user = self.request.cookies.get('username')
        if(user == None):
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
        if(name and password and email and user_password == user_verify):
            # user_password_hash =

            u = Users(user = user_name, password = user_password, email = user_email)
            k = u.put()

            self.response.headers['Content-Type'] = "text/plain"
            username = str(user_name)
            self.response.headers.add_header('Set-Cookie', 'username=%s' % username + '; Path:/')
            self.redirect("/blog/welcome")
        else:
            self.render("signup.html", username = user_name,
                                password = user_password,
                                email = user_email,
                                verify = user_verify,
                                error_email = error_email,
                                error_password = error_password,
                                error_username = error_username,
                                error_verify = error_verify)

class WelcomeHandler(Handler):
    def get(self):
        username = self.request.cookies.get("username")
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
            b = Blog(subject = subject, content = content)
            k = b.put()
            index = k.id()
            link = "/blog/" + str(index)
            self.redirect(link)
        else:
            error = "We both need a subject and a post"
            self.render_newpost(subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/blog?', BlogHandler),
                                ('/blog/welcome', WelcomeHandler),
                                ('/blog/(\d+)', PostHandler),
                                ('/blog/signup', SignupHandler),
                                ('/blog/newpost', NewPostHandler)], debug=True)
