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

from google.appengine.ext import ndb

# define jinja2 environment
DEBUG_Control = True
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
def log_out(*a, **kw):
    if DEBUG_Control:
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
    

def post_key(group = 'default'):
    return ndb.Key('Post', group)
class Post(ndb.Model):
    content = ndb.TextProperty(required = True)
    post_id = ndb.StringProperty(required = True) # the name of the post
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    version = ndb.StringProperty(required = True)
    
    @classmethod
    def query_ancestor(cls, ancestor_key):
        return cls.query(ancestor = ancestor_key).order(-cls.created)
def render_text(content):
    return content.replace('\n', '')
        
        
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render(self, template, **kw):
        self.write(render_str(template, **kw))
        
    def set_secure_cookie(self, cookie_name, val):
        cookie_val = ''
        if val:
            cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s' % (cookie_name, cookie_val))
    
    def read_cookie(self, cookie_name):
        cookie_val = self.request.cookies.get(cookie_name)
        return cookie_val and check_secure_val(cookie_val)
         
    def set_cookie(self, user):
        self.set_secure_cookie('user_id', int(user.key.id()))
    
    def delete_cookies(self):
        self.set_secure_cookie('user_id', '')
    
    def validate(self):
        user_id = self.read_cookie('user_id')
        log_out('user_id', user_id)
        if user_id:
            return User.by_id(int(user_id))
    def set_post_cookie(self, post_id='', version=''):
        self.response.headers.add_header('Set-Cookie','%s=%s' %('post_id', str(post_id)))
        self.response.headers.add_header('Set-Cookie','%s=%s' %('version', str(version)))
    def read_post_cookie(self):
        p = self.request.cookies.get('post_id')
        v = self.request.cookies.get('version')
        return p, v
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class WikiPage(BlogHandler):
    def set_url_before_login(self): 
        self.response.headers.add_header('Set-Cookie', '%s=%s' % ('url_login', self.request.url))
    def get(self, post_id):
        self.set_url_before_login()
        version = self.request.get('v')
        user = self.validate()
        post_name = post_id.split('/')[1]
        log_out(post_name)
        q = Post.query_ancestor(post_key()).filter(Post.post_id == post_id)
        if version:
            q = q.filter(Post.version == version)
            self.set_post_cookie(post_id, version)
        else:
            self.set_post_cookie()
        post = q.get()
        if post:
            self.render('post.html', p=post, user=user)
        else:
            self.redirect('/_edit' + post_id)

class EditPage(BlogHandler):
    def get(self, post_id):
        user = self.validate()
        if user:
            #version = self.request.get('v')
            post_id_cookie, version = self.read_post_cookie()
            q = Post.query_ancestor(post_key()).filter(Post.post_id == post_id)
            if post_id == post_id_cookie and version:
                q = q.filter(Post.version == version)
            post = q.get()
            if post and post.content:
                self.render('editpage.html', p=post, user=user)
            else:
                self.render('editpage.html', p=None, user=user)
        else:
            self.response.headers.add_header('Set-Cookie', '%s=%s' % ('rdrted-from', 'ppoooo'))
            log_out('url', self.request.url)
            self.redirect('/login')
    def post(self, post_id):
        user = self.validate()
        if user:
            content = self.request.get('content')
            q = Post.query_ancestor(post_key()).filter(Post.post_id == post_id)
            post = q.get()
            if content:
                content = render_text(content)
                if post:
                    version = int(post.version) + 1
                else:
                     version = 1
                post = Post(content = content, post_id=post_id, version=str(version), parent=post_key())
                post.put()
                self.redirect(post_id)
        else:
            self.redirect('/login')

class HistoryPage(BlogHandler):
    def get(self, post_id):
        user = self.validate()
        if user:
            self.p_id = post_id
            q = Post.query_ancestor(post_key()).filter(Post.post_id == post_id)
            posts = list(q)
            log_out('posts', posts[0].content)
            self.render('historypage.html', posts=posts, user=user)
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# generate root Key, all new User entity parent key is this one
def user_key(group='default'):
    return ndb.Key('User', group)
    
class User(ndb.Model):
    name = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=False)
    
    # class method, query by name
    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        return u
    @classmethod
    def by_id(cls, uid):
        u = User.get_by_id(int(uid), parent = user_key())
        log_out(u)
        return u
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
        user = User.by_name(self.username)
        if user:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()
            self.set_cookie(user)
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
        log_out(username, password, **params)
        if have_error:
            self.render('login-form.html', **params)
            
        else:
            user = User.validate_name_pw(username, password)
            if user:
                self.set_cookie(user)
                post_id, version = self.read_post_cookie()
                url = self.request.cookies.get('url_login')
                self.redirect(str(url))
            else:
                error = "Username and password didn't match"
                self.render('login-form.html', **params)
class Logout(BlogHandler):
    def get(self):
        self.delete_cookies()
        self.redirect('/')
class Welcome(BlogHandler):
    def get(self):
        user = self.validate()
        if user:
            self.render('welcome.html', username = user.name)
        else:
            self.redirect('/')

class ViewVersionPage(BlogHandler):
    def get(self, post_id, version):
        log_out(post_id, version)
class MainHandler(BlogHandler):
    def get(self):
        self.render('mainpage.html')
        
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
    ('/_edit' + PAGE_RE, EditPage),
    ('/_history' + PAGE_RE, HistoryPage),
    #('/history' + PAGE_RE + '?v=([0-9]+)', ViewVersionPage),
    (PAGE_RE, WikiPage)

], debug=True)
