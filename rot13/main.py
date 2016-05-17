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
form ="""
<form method="post">
    The result of Rot13:<br>
    <textarea name="text" rows="4" cols="50">%(inputtext)s</textarea><br>
    <input type="submit">
</form>
"""
def escape_html(s):
    for (i, o) in (('&', "&amp;"),
                   (">", "&gt;"), 
                   ("<", "&lt;"), 
                   ('"', "&quot;")):
        s = s.replace(i, o)
    return s

def encode(string):
    result = ""
    for c in string:
        if (ord(c) >=65 and ord(c) <= 90):
            result += chr(ord("A") + (ord(c) - ord("A") + 13) % 26)   
        elif (ord(c) >= 97 and ord(c) <= 122):
            result += chr(ord("a") + (ord(c) - ord("a") + 13) % 26)
        else:
            result += escape_html(c)
    return result

class MainHandler(webapp2.RequestHandler):
    def write_form(self, text=""):
        self.response.write(form % {"inputtext": text})
    def get(self):
        self.write_form()
    def post(self):
        self.write_form(encode(self.request.get("text")))
        
app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
