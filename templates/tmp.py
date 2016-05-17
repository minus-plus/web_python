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

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))
form_html = """
<form>
 <h1>Add a food</h1>
 <input type="text" name="food">
 %s
 <button>Add</button>
</form>
"""
hidden_html = """
<input type="hidden" name="food" value="%s">
"""
item_html = "<li>%s</li>"
shopping_list_html = """
<br>
<br>
<h2> Shopping List</h2>
<ul>
%s
</ul>
"""
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(**params)
    def render(self, template, **kw):
        self.render_str(template, **kw)

class MainHandler(Handler):
    def get(self):
        self.render("shoppinglist.html")
        output = form_html
        output_hidden = ""
        items = self.request.get_all("food")
        output_items = ""
        if items:
            for item in items:
                output_hidden += hidden_html % item
                output_items += item_html % item
        output_shopping_list = shopping_list_html % output_items
        output = output % output_hidden
        output += output_shopping_list
        self.write(output)

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
