#!/usr/bin/env python
import os
import re
import random
import hashlib
import hmac
from string import letters
import json

import webapp2
import jinja2  
import logging

from google.appengine.ext import db
from google.appengine.api import memcache
from datetime import datetime, timedelta

# define jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
# unit 6 caching part

    
secret = 'fart'
def render_str(template, **kw):
    return jinja_env.get_template(template).render(**kw)

def make_secure_val(val):
    return '%s|%s'% (val, hmac.new(secret, str(val)).hexdigest())
def check_secure_val(cookie_val):
    val = cookie_val.split('|')[0]
    if cookie_val == make_secure_val(val):
        return val
    
class BlogHandler(webapp2.RequestHandler):
    def render_str(self, template, **kw):
        t = jinja_env.get_template(template)
        t.render(**kw)
        
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    
    # used to write content to response object
    def render(self, template, **kw):
        self.write(render_str(template, **kw))
    
    # render json
    def render_json(self, content):
        # content could be list or dictionary
        json_txt = json.dumps(content)
        self.request.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)
    # cookie part
    def set_secure_cookie(self, name, val):
        cookie_val = ''
        if val:
            cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                    '%s=%s; Path=/' % (name, cookie_val))
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    def setCookie(self, user):
        self.set_secure_cookie('user_id', user.key().id())
    
    def deleteCookie(self):
        self.set_secure_cookie('user_id', '')
    
    def validate(self):
        cookie_val = self.read_secure_cookie('user_id')
        if cookie_val:
            u_id = cookie_val.split(',')[0]
            return User.by_id(int(u_id))
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        logging.info('--------the web page initializing-------')
        
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'
        
        
        
class MainPage(BlogHandler):
    def get(self):
        self.response.write('Hello, Udacity!')
        
# user database
# hash pw
def make_salt(length):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt(5)
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)
    
def vaid_pw(name, pw, hash_str):
    salt = hash_str.split(',')[0]
    return make_pw_hash(name, pw, salt) == hash_str
def users_key(group='default'):
    return db.Key.from_path('users', group) # 'users' means table named 'user', return parent key
    
class User(db.Model):
    #attributes
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    
    # class method for the convenience to query
    @classmethod
    def by_name(cls, name):
        logging.info('in by_name() username is %s' % name)
        u = User.all().filter('name =', name).get()
        # error here, filter('name=', name) should be filter('name =', name). otherwise 'name=' will be treated as on word
        return u
    @classmethod
    def by_id(cls, uid): # still not clear
        return User.get_by_id(int(uid), parent = users_key())
    @classmethod
    # construct and return user when register
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        u = User(parent=users_key(),
                 name=name,
                 pw_hash=pw_hash,
                 email=email)
        return u
    
    @classmethod
    # query and return user when login
    def validate_name_pw(cls, name, pw):
        u = cls.by_name(name)
        if u and vaid_pw(name, pw, u.pw_hash):
            return u
# blog stuff

    

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

    
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        post_url = '/blog/%s' % str(self.key().id())
        return render_str("post.html", p = self, post_url = post_url)
    
    def as_dict(self):
        # aimed to convert a post to json(dict or list of dict)
        time_fmt = '%c'
        content = {'subject': self.subject,
                   'content': self.content,
                   'created': self.created.strftime(time_fmt),
                   'last_modified': self.last_modified.strftime(time_fmt)}
        return content
        
# caching
def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))
    
def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0
    return val, age
    
def add_post(post):
    post.put()
    get_posts()
    return str(post.key().id())
    
def get_posts(update=False):
    # query the posts
    key = 'BLOGS'
    posts, age = age_get(key)
    if not posts or update:
        # do db query
        logging.error('DB Query')
        posts = Post.all().order('-created').fetch(limit=10)
        posts = list(posts)
        age_set(key, posts)
    return posts, age
    
    
def age_str(age):
    s = "queried %s seconds ago"
    age = int(age)
    if age == 1:
        s.replace('seconds', 'second')
    return s % age
    
class BlogFront(BlogHandler):
    def get(self):
        posts, age = get_posts()
        # posts = greetings = Post.all().order('-created')
        if self.format == 'html':
            age = age_str(age)
            self.render('front.html', posts = posts, age = age)
        elif self.format == 'json':
            self.render_json([p.as_dict() for p in posts])

class PostPage(BlogHandler):
    def get(self, post_id):
        mc_key = 'POST' + post_id
        post, age = age_get(mc_key)
        
        if not post:
            # post was never cached before
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)
            age_set(mc_key, post)
            age = 0
            if not post:
                self.error(404)
                return
        if self.format == 'html':
            age = age_str(age)
            self.render("permalink.html", post = post, age = age)
        elif self.format == 'json':
            self.render_json(post.as_dict())

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            post_id = add_post(p)
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class Flush(BlogHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')
            
# hw4 part
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    """
    about logging, first import logging, then use logging.debug(), info(), warning(), error(), critical() to write message to log.
    debug() would not show in log by default
    """
        
    def get(self):
        self.render('signup-form.html')
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        # in order show username and email when invalid input
        params = dict(username=self.username, email=self.email)
        
        logging.info('params is %s' % str(params))
        logging.info('self.username is %s' % self.username)
        if not valid_username(self.username):
            params['error_username'] = "That wasn't a valid username."
            have_error = True
        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.verify != self.password:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
    
    def done(self, *a, **kw):
        raise NotImplementedError
        
class Register(Signup):
    # check if user has been exist
    def done(self):
        logging.info("in done() username is %s" % self.username)
        u = User.by_name(self.username)
        if u:
            logging.info("user already exist")
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            user = User.register(self.username, self.password, self.email)
            # user.put() will return the key of the User entity
            key = user.put()
            logging.info('key is %s, id is %d' % (key, key.id()))
            logging.info(key.parent())
            self.setCookie(user)
            self.redirect('/welcome')
    
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        params = {}
        have_error = False

        if not valid_password(password):
            have_error = True
        else:
            if not valid_username(username):
                have_error = True
                params['error_username'] = 'Not a valid username!'
        if have_error:
            self.render('login-form.html', **params)
            
        else:
            user = User.validate_name_pw(username, password)
            if user:
                self.setCookie(user)
                self.redirect('/blog')
            else:
                error = "Username and password didn't match"
                self.render('login-form.html', **params)
   
    
class Logout(BlogHandler):
    def get(self):
        self.deleteCookie()
        self.redirect('/blog')
        
    
class Welcome(BlogHandler):
    def get(self):
        user = self.validate()
        if user:
            self.render('welcome.html', username = user.name)
        else:
            self.redirect('/blog')
    
        
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
                               ('/flush', Flush)
                               ], debug=True)        
        
  