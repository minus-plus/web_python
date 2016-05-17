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
from string import letters
import hashlib

import webapp2
import jinja2

from google.appengine.ext import db

# set jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# hash the string and return "s|HASH"
def hash_str(s):
    return hashlib.md5(s).hexdigest()
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))
def check_secure_val(h):
    val = h.split('|')[0]
    if make_secure_val(val) == h:
        return val
# hash with salt
# salt is a five letters word
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
def make_hash_salt(username, pw):
    salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
        
    def render_str(self, template, **kw):
        t = jinja_env.get_template(template)
        return t.render(**kw)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# main page
class MainHandler(Handler):
    def get(self):
        self.response.write('Hello udacity!')

        
# sign-up page
class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
    
class SignUpHandler(Handler):
    def get(self):
        # get username from cookie and chech if it is valid
        user_cookie_str = self.request.cookies.get('user')
        if user_cookie_str:
            user_cookie_val = check_secure_val(user_cookie_str)
            if user_cookie_val:
                self.redirect('/welcome')
        
        # if not, send sign-up form to user?
        self.render('sign-up.html')
    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
            
        params = dict(username = username, email = email)
        
        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords do not match."
            have_error = True
        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        
        if(have_error):
            self.render('sign-up.html', **params)
        else:
            user = User(username=username, password=password, email=email)
            user.put()
            new_user_cookie_val = make_secure_val(str(username))
            self.response.headers.add_header('Set-Cookie', 'user=%s' % new_user_cookie_val, path='/')
            self.redirect('/welcome')
class WelcomeHandler(Handler):
    def get(self):
        #username = self.request.get('username')
        cookie_str = self.request.cookies.get('user')
        username = check_secure_val(cookie_str)
        self.write('Welcome, %s!' % username)
class LogoutHandler(Handler):
    def get(self):
        cookie_str = str(self.request.cookies.get('user'))
        self.response.headers.add_header('Set-Cookie', 'user= %s' % cookie_str, expires='Thu, 01 Jan 1970 00:00:00 GMT', path='/')
        self.redirect('/log-in')
class LoginHandler(Handler):
    def get(self):
        # get username from cookie and chech if it is valid
        user_cookie_str = self.request.cookies.get('user')
        if user_cookie_str:
            user_cookie_val = check_secure_val(user_cookie_str)
            if user_cookie_val:
                self.redirect('/welcome')
        # if not, send sign-up form to user?
        self.render('log-in.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        params = dict(username=username)
        is_valid = True
        if not valid_username(username):
            params['error_username'] = "Username is invalid."
            is_valid = False
        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            is_valid = False
        if not is_valid:
            params['error'] = ''
            self.render('log-in.html', **params)
        else:
            #users = User.gql("where filter = :username", username = username)
            users = db.GqlQuery("select * from User where username = :1", username)
            user = users.get()
            have_error = False
            if not user:
                have_error = True
                params['error'] = "Username doesn't exist!"
            elif user.password != password:
                have_error = True
                params['error'] = "Username and password don't match!"
            
            if have_error:
                self.render('log-in.html', **params)
            else:
                new_cookie_str = make_secure_val(str(username))
                self.response.headers.add_header('Set-Cookie', 'user=%s' % new_cookie_str, path='/')
                self.redirect('/welcome')
        

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/sign-up', SignUpHandler),
    ('/welcome', WelcomeHandler),
    ('/log-out', LogoutHandler),
    ('/log-in', LoginHandler)
], debug=True)
