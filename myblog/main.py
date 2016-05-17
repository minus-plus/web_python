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

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
# doesn't work now
def render_post(response, post): # for the post.html
    response.write('<b>' + post.subject + '</b><br>')
    response.write(post.content)
    
class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.write("Hello, Undacity!")

# the parent class   
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)  
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
# the db model kind
class Post(db.Model): # define the type of data base, Now Blog is a table
    # filds in Blog table
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    def render_in_post(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', post = self)

# still don't know how it works
def blog_key(name = "default"):
    return db.Key.from_path("blogs", name)
    
# deal with request for main page   
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render("front.html", posts = posts) # loop: render blogs into front.html and return back
        
# deal with request for newpost page    
class NewPost(BlogHandler): # newpost is a form used to submit new post 
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
    def get(self):
        self.render_newpost() # deal with when submmit is error, re-present subject, blog and error message
    def post(self): # if client request to post a form to server, handler do the following operations
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            p = Post(parent = blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Need both subject and blog content"
            self.render_newpost(subject, content, error)
class PostPage(BlogHandler):
    def get(self, post_id):
        # where the post_id comes from?
        # comes from p.key().id
        # p.key() get the Key object of p
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, post_id = post_id)
        
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage), 
                               ('/blog/newpost', NewPost)
                               
], debug=True)
