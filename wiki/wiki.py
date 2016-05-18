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

def render_str(template, **kw):
    t = jinja_env.get_template(template)
    logging.info(t)
    logging.info(kw)
    return t.render(**kw)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        logging.info(a)
        logging.info(kw)
        self.response.write(*a, **kw)
    def render(self, template, **kw):
        self.write(render_str(template, **kw))
class Welcome(BlogHandler):
    def get(self):
        self.response.write('Welcome to Wiki!')
class NewPost(BlogHandler):
    def get(self):
        #self.response.write('hello')
        self.render("post.html")
class EditPage(BlogHandler):
    def get(self, post_name):
        self.render('editpage.html')
class MainHandler(BlogHandler):
    def get(self):
        self.response.write('Hello Udacity!')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPost),
    ('/welcome', Welcome),
    ('/_edit/([a-zA-Z0-9_-]+)', EditPage)
], debug=True)
