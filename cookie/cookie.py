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
import webapp2
from string import letters
import random


import jinja2

from google.appengine.ext import db



template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False) 

# hashing part
import hashlib

def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):

    val = h.split('|')[0]
    if make_secure_val(val) == h:
        return val
    
# hash password and use salt
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

class Handler(webapp2.RequestHandler):
    def write(self, *a):
        self.response.write(*a)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)  
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def get(self):
        self.response.headers['Content-type'] = 'text/plain'
        visits = 0
        # visit_cookie_str is "s,HASH" or none
        visit_cookie_str = self.request.cookies.get('visits')
        if visit_cookie_str:
            # return str or none
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_visit_cookie_str = make_secure_val(str(visits))
        self.response.headers.add_header("Set-Cookie", "visits=%s" % new_visit_cookie_str)
        if visits > 10000:
            self.write("you are our best user!")
        else:
            self.write("you have been here %s times!" % visits)

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
