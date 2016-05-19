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
            self.render('editpage.html')
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
                p.put()
            self.redirect(post_id)
            
            
class MainHandler(BlogHandler):
    def get(self):
        self.response.write('Hello Udacity!')
        
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage)
], debug=True)
