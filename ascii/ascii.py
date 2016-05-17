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
import time
import logging
import urllib2

import json
from xml.dom import minidom

import requests

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = False)

IP_URL = 'http://ip-api.com/json/'

def get_coords(ip):
    ip = '4.4.4.2'
    url = IP_URL + ip
    content = None
    #logging.info('get_coords is called')
    try:
        page = urllib2.urlopen(url)
        content = page.read()
        dic = json.loads(content)
        #logging.info('try part')
        #dic = json.loads(content)
        #logging.info('dic is %s' % dic)
    except urllib2.URLError:
        return
    if dic:
        lat = dic['lat']
        lon = dic['lon']
        return db.GeoPt(lat, lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmap_img(points):
        markers = '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)
        return GMAPS_URL + markers

            
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)  
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

art_key = db.Key.from_path('ASCIIChan', 'arts')
class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()
    
def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
        # run db Query
        logging.error('DB Query')
        arts = db.GqlQuery("SELECT * "
                        "FROM Art "
                        "WHERE ANCESTOR IS :1 "
                        "ORDER BY created DESC "
                        "LIMIT 10",
                        art_key)
        arts = list(arts)
        memcache.set(key, arts)
        arts = memcache.get(key)

    return arts
        
CACHE = {} 
def top_arts_cache(update=False):
    if not update and key in CACHE:
        arts = CACHE[key]
        
    else:
        logging.error('DB Query')
        arts = db.GqlQuery("SELECT * "
                            "FROM Art "
                            "ORDER BY created DESC "
                            "LIMIT 10")
        # list(arts) to prevent multiple queries
        arts = list(arts)
        CACHE[key] = arts
        logging.error('cache is %s' % CACHE)
    return arts
    
class MainHandler(Handler):
    def render_front(self, title="", art="", error=""):
        #logging.info(title)
        arts = top_arts()
        
        img_url = None
        points = filter(None, [a.coords for a in arts])
        #logging.info('points are %s' % points)
        if points:
            img_url = gmap_img(points)
            #logging.info('img_url is %s' % img_url)
        # add an image to the page
        self.render("front.html", title=title, art=art, error=error, arts=arts, img_url=img_url)
        
    def get(self):
        #self.write(self.request.remote_addr)
        #self.write(repr(get_coords(self.request.remote_addr)))
        self.render_front()
        
    def post(self):

        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(parent=art_key, title=title, art=art)
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords
            a.put()
            #time.sleep(0.1)
            top_arts(True)
            self.redirect("/")
        else:
            error = "should have both title and art"
            self.render_front(title=title, art=art, error=error)
            
app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
