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
import re
import os

import webapp2
global user
user = ""
form="""
<form method="post">
    <table>
        <tr>
            <td>
            Username:
            </td>
            <td>
            <input type="text" name="username" value=%(username)s>%(user_error)s
            </td> 
        </tr>
        <tr>
            <td>Password:</td>
            <td>
            <input type="password" name="password" value=%(password)s>%(pass_error)s
            </td>
        </tr>
        <tr>
            <td>
            Verify password:
            </td>
            <td>
            <input type="password" name="password_v" value=%(password_v)s>%(pass_v_error)s
            </td>
        </tr>
            <tr>
            <td>
            Email:
            </td>
            <td>
            <input type="email" name="email" value=%(email)s>%(email_error)s
            </td>
        </tr>
    </tabel><br>
    
    <input type="submit">
</form>
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

def valid_password_v(password, password_v):
    return valid_password(password) and (password == password_v)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email and EMAIL_RE.match(email)

class MainHandler(webapp2.RequestHandler):
    def write_form(self, username="", user_error="", 
                   password="", pass_error="", 
                   password_v="", pass_v_error="", 
                   email="", email_error=""):
        self.response.write(form % {"username": username, "user_error": user_error, 
                                    "password": password, "pass_error": pass_error, 
                                    "password_v": password_v, "pass_v_error": pass_v_error, 
                                    "email": email, "email_error": email_error})
    def get(self):
        self.write_form()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        password_v = self.request.get("password_v")
        email = self.request.get("email")
        u = valid_username(username)
        p = valid_password(password)
        p_v = valid_password_v(password, password_v)
        e = valid_email(email)
        user_error = ""
        pass_error = ""
        pass_v_error = ""
        email_error = ""
        if not u:
            user_error = "Not a valid username."
        if not p:
            pass_error = "Not a valid password."
        if p and not p_v:
            pass_v_error = "Password does not match."
        if not e:
            email_error = "Not a valid email address."
        if (u and p and p_v and e):
            global user
            user = self.request.get("username")
            self.redirect('/welcome')
        else:
            self.write_form(username,user_error, password, pass_error, password_v, pass_v_error, email, email_error)
class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        global user
        user = user + ", welcome login!"
        self.response.write(user, " are you ok?")
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/welcome', WelcomeHandler)
], debug=True)
