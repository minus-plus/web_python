#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import logging

from google.appengine.ext import db

# define jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
def log_out(*a, **kw):
    logging.info('++++++++++++++++++++++++++++++++++++++++++++++++')
    logging.info(a)
    logging.info(kw)
    logging.info('================================================')
#+++++++++++++++++++++++++++++++++++++++++++++
# hash
secret = 'fart'
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, str(val)).hexdigest())

def check_secure_val(cookie_val):
    val = cookie_val.split('|')[0]
    if make_secure_val(val) == cookie_val:
        return val
        
        
def make_salt(length):
    return ''.join(random.choice(letters) for x in range(length))
    
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt(5)
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def validate_pw(name, pw, pw_hash):
    salt = pw_hash.split(',')[0]
    return make_pw_hash(name, pw, salt) == pw_hash


def render_str(template, **kw):
    t = jinja_env.get_template(template)
    return t.render(**kw)
    
def wiki_key(name = 'default'):
    return db.Key.from_path('wikipages', name)

class Post(db.Model):
    content = db.TextProperty(required = True)
    post_id = db.StringProperty(required = True) # the name of the post
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
def render_text(content):
    return content.replace('\n', '')
        
        
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render(self, template, **kw):
        self.write(render_str(template, **kw))


class WikiPage(BlogHandler):
    def get(self, post_id):
        post_name = post_id.split('/')[1]
        logging.info(post_name)
        q = db.GqlQuery("SELECT * FROM Post WHERE post_id = :1", post_id)
        post = q.get()
        if post:
            self.render('post.html', p=post)
        else:
            self.redirect('/_edit' + post_id)
            
            
class EditPage(BlogHandler):
    def get(self, post_id):
        self.p_id = post_id
        q = db.GqlQuery("SELECT * FROM Post WHERE post_id = :1", post_id)
        post = q.get()
        if post and post.content:
            logging.info(post.content)
            self.render('editpage.html', p=post)
        else:
            self.render('editpage.html', p=None)
    def post(self, post_id):
        content = self.request.get('content')
        q = db.GqlQuery("SELECT * FROM Post WHERE post_id = :1", post_id)
        post = q.get()
        if content:
            content = render_text(content)
            if post:
                post.content = content
                post.put()
            else:
                p = Post(content = content, post_id=post_id)
                logging.info(render_text(content))
                p_key = p.put()
                logging.info('+++++++++++++++++++++++++++++++++++++')
                logging.info(p_key)
                logging.info(p_key.id())
            self.redirect(post_id)
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# generate root Key, all new User entity parent key is this one
def user_key(group='default'):
    return db.Key.from_path('User', group)
    
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    
    # class method, query by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(int(uid))
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        u = User(parent=user_key(), name=name, pw_hash=pw_hash, email=email)
        return u
    @classmethod
    def validate_name_pw(cls, name, pw):
        u = cls.by_name(name)
        log_out('user', u)
        if u and validate_pw(name, pw, u.pw_hash):
            return u
    
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
    def get(self):
        self.render('signup-form.html')
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        params = dict(username=self.username, email=self.email)
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
            
    def done(self):
        raise NotImplementedError
class Register(Signup):
    def done(self):
        #check if username has exist or not
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.redirect('/welcome')
class Welcome(BlogHandler):
    def get(self):
        self.response.write('welcome')
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
        log_out(username, password, **params)
        if have_error:
            self.render('login-form.html', **params)
            
        else:
            user = User.validate_name_pw(username, password)
            if user:
                self.redirect('/welcome')
            else:
                error = "Username and password didn't match"
                self.render('login-form.html', **params)
          
        
class MainHandler(BlogHandler):
    def get(self):
        self.response.write('Hello Udacity!')
        
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', Register),
    ('/login', Login),
    ('/welcome', Welcome),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage)

], debug=True)
