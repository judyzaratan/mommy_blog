import os
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def get(self):
        self.render('index.html')

class BlogHandler(Handler):
    def get(self):
        self.render("blog.html")

class NewPostHandler(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newPost.html", subject=subject, content=content, error=error)
    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            self.write("thanks!")
        else:
            error = "We both need a subject and a post"
            self.render_newpost(subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/blog', BlogHandler),
                                ('/newpost', NewPostHandler)], debug=True)
