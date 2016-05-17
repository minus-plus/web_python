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
import webapp2
import os
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)  
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    blog = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    
class MainHandler(Handler):
    def render_post(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        self.render("blog.html", blogs=blogs)
    def get(self): # if client(i.e. browser) request to get the website, handler do the following operations
        self.render_post()
        
    
class NewPostHandler(Handler):
    def render_newpost(self, subject="", blog="", error=""):
        self.render("newpost.html", subject=subject, blog=blog, error=error)
    def get(self):
        self.render_newpost() # deal with when submmit is error, re-present subject, blog and error message
    def post(self): # if client request to post a form to server, handler do the following operations
        subject = self.request.get("subject")
        blog = self.request.get("blog")
        if subject and blog:
            b = Blog(subject=subject, blog=blog)
            b.put()
            self.response.write("post success")
        else:
            error = "Need both subject and blog content"
            self.render_newpost(subject, blog, error)
            
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/newpost', NewPostHandler)
], debug=True)
