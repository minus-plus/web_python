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


form="""
<form method="post">
What is you birthday?<br>
    <label>Month<input name="month" value="%(month)s"></label>
    <label>Day<input name="day" value="%(day)s"></label>
    <label>Year<input name="year" value="%(year)s"></label>
    <div style="color:red">%(error)s</div>
    <input type="submit">
</form>
"""

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']
month_abbvs = dict((m[:3].lower(), m) for m in months)
def valid_month(month):
    if month:
        short_month = month[:3].lower()
        return month_abbvs.get(short_month)
def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day >= 1 and day <= 31:
            return day
def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if year >= 1900 and year <= 2020:
            return year
def escape_html(s):
    for (i, o) in (('&', "&amp;"),
                   (">", "&gt;"), 
                   ("<", "&lt;"), 
                   ('"', "&quot;")):
        s = s.replace(i, o)
    return s
    
        
class MainHandler(webapp2.RequestHandler):
    def write_form(self, error="", month="", day="", year=""):
        self.response.write(form % {"error": error, "month": escape_html(month)
                                    , "day": escape_html(day), "year":escape_html(year)})
    def get(self):
	#self.response.headers['Content-Type'] = 'text/html'
        self.write_form("")

    def post(self):
        user_month = valid_month(self.request.get("month"))
        user_day = valid_day(self.request.get("day"))
        user_year = valid_year(self.request.get("year"))
        m = self.request.get("month")
        d = self.request.get("day")
        y = self.request.get("year")
        if not (user_month and user_day and user_year):
            self.write_form("it is not a valid date!", m, d, y)
        else:
            self.redirect("/thanks")
class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write("Thanks, it is a valid date!")
          
app = webapp2.WSGIApplication([
    ('/', MainHandler), ('/thanks', ThanksHandler)], debug=True)
