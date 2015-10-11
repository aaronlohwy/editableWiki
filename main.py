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

## THINGS TO DO : 1) Implement CAS for memcache to blog
# FINAL!!! http://aaronblogudacity.appspot.com/blog/newpost

import webapp2
from webapp2_extras import routes
import os
import jinja2
from google.appengine.ext import db
from google.appengine.api import memcache
import time
import json
import re
import string
import hashlib
import hmac
import random
import logging

SECRET = "imsosecret" #you would actually keep this in a private module

jinja_env = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

#cookie functions!!
def make_salt():
    return ''.join(random.choice(string.ascii_letters) for i in range(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)
    
def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

def get_salt(passwordhash):
    salt = passwordhash.split(',')[1]
    return salt

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return s + "|" + hash_str(s)

def check_secure_val(h):
   val = h.split('|')[0]
   if h == make_secure_val(val):
    return val
################
######## CACHE FUNCTIONS!!! ##############
start_time = time.time()

def cachedBlogPosts(update=False):
    key= 'top'
    posts = memcache.get(key)
    if posts is None or update:
        global start_time
        start_time=time.time()
        logging.error("DB Query")
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC") #can also do order by created DESC limit 10
        posts = list(posts) #changes the cursor to a list, safer, prevent the running of multiple queries.
        memcache.set(key,posts)
    return posts


## CACHING PERMALINK...
permalinkcachetimes = {}

def cachedPermaLink(post_id, update=False):
    key= post_id
    blogPost = memcache.get(key)
    if blogPost is None or update:
        mostrecentquerytime=time.time()
        permalinkcachetimes[post_id]=mostrecentquerytime
        logging.error("DB Query")
        blogPost = BlogPost.get_by_id(int(post_id))
        memcache.set(key,blogPost)
    mostrecentquerytime = permalinkcachetimes[key]
    return blogPost , mostrecentquerytime
##############################

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	def render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

class WikiPage(db.Model):
    content = db.TextProperty(required=True)
    page_name = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now = True)

class MainHandler(Handler):
    def render_mainpage(self):
    	blogPosts= cachedBlogPosts()
        elapsedtime = time.time() - start_time
    	self.render("mainblog.html", blogPosts = blogPosts, elapsedtime=elapsedtime)

    def get(self):
    	self.render_mainpage()

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id_str = self.request.cookies.get('user_id')
        if user_id_str:
            cookie_val = check_secure_val(user_id_str)
            if cookie_val:
                self.loggedin_user = User.get_by_id(int(cookie_val))
            else:
                self.loggedin_user = False
        else:
            self.loggedin_user=False

############## CACHE FLUSH HANDLER ################
class FlushHandler(MainHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')

####################################################
################################################## LOG IN HANDLERS ################################################
USER_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_REGEX.match(username)

PASSWORD_REGEX = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_REGEX.match(password)

EMAIL_REGEX  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_REGEX.match(email)

class SignupHandler(MainHandler):
    def get(self):
        self.render('signupform.html')

    def post(self):
        error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verifiedpassword = self.request.get('verify')
        email = self.request.get('email')

        error_username=""
        error_email=""
        error_password=""
        error_passwordmatch=""

        if not valid_username(username):
            error_username = "invalid username!"
            error= True
        if not valid_email(email):
            error_email = "invalid email!"
            error= True
        if not valid_password(password):
            error_password = "invalid password!"
            error= True
        if password!=verifiedpassword:
            error_passwordmatch="passwords do not match!"
            error= True

        if error:
            self.render('signupform.html', username=username, email=email, error_username = error_username, error_password=error_password,error_passwordmatch=error_passwordmatch,error_email=error_email)
        else:
            user = db.GqlQuery("SELECT * FROM User WHERE name = '%s'" %username).get() #check to see if user already exists
            if user: 
                error_username = "that username already exists!"
                self.render('signupform.html', username=username, email=email, error_username = error_username, error_password=error_password,error_passwordmatch=error_passwordmatch,error_email=error_email)
            else:
                user = User(name=username, pw_hash=make_pw_hash(username,password))
                user.put()
                user_id = user.key().id()  # figure out permalinks!
                user_cookie = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id = %s ; Path =/'%user_cookie )
                self.redirect('/welcome')

class LoginHandler(MainHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        error_login = ""
        username = self.request.get('username')
        password = self.request.get('password')

        user = db.GqlQuery("SELECT * FROM User WHERE name = '%s'" %username).get()

        if not user:
            error_login = "Invalid Login!"
            self.render('login.html', error_login = error_login)
        else:
            salt = get_salt(user.pw_hash)
            if user.pw_hash != make_pw_hash(username,password,salt):
                error_login = "Invalid Login!"
                self.render('login.html', error_login = error_login)
            else:
                user_id = user.key().id()
                user_cookie = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id = %s ; Path =/'%user_cookie )
                self.redirect('/welcome')

class LogoutHandler(MainHandler):
    def get(self,page_name):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('%s'%page_name)
        #self.redirect('/%s'%self.page_name)

class WelcomeHandler(MainHandler):  
    def get(self):
        user_id_str = self.request.cookies.get('user_id')
        if user_id_str:
            cookie_val = check_secure_val(user_id_str)
            if cookie_val:
                user = User.get_by_id(int(cookie_val))
                self.render('signup.html', username = user.name)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')
##################################################  END OF LOG IN HANDLERS ################################################
###################################### BLOG HANDLERS########################
class PostHandler(MainHandler):
    def render_postpage(self, subject = "", content = "", error=""):
        self.render("newpost.html", subject = subject, content = content, error=error)

    def get(self):
        self.render_postpage()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            bp = BlogPost(subject=subject, content=content)
            bp.put()
            postID = bp.key().id()  # figure out permalinks!
            time.sleep(1) # not always good form to sleep, cuz you make the user wait. I put it just so when the page reloads the data is sure to be there! else the write might come before the art is put inside the database. it will eventually be consistent anyway. check out http://forums.udacity.com/questions/100044559/ascii-page-requires-a-reload-before-a-new-submission-is-displayed-why-ascii_chan-unit-3#cs253 
            cachedBlogPosts(True) #caching
            self.redirect("/%s" % postID)
        else:
            error = "we need both a subject and some content!"
            self.render_postpage(subject,content,error)

class PermaLinkHandler(MainHandler):
    def render_permalink(self, post_id):
        blogPost , mostrecentquerytime= cachedPermaLink(post_id)
        elapsedtime = time.time() - mostrecentquerytime
        self.render("permalink.html", blogPost=blogPost, elapsedtime=elapsedtime)

    def get(self, post_id):
        self.render_permalink(post_id)
        #http://webapp-improved.appspot.com/guide/routing.html
        #https://cloud.google.com/appengine/docs/python/datastore/modelclass#Model_get_by_id


################# JSON HANDLERS #####################################################
class JSONHandler(MainHandler):
    def get(self,post_id):
        self.response.headers["Content-Type"] = "application/json"
        if post_id:
            bp = BlogPost.get_by_id(int(post_id))
            jsondict = {"content": bp.content, "created": bp.created.strftime("%a, %d %b %Y %H:%M:%S"),"last_modified": bp.last_modified.strftime("%a, %d %b %Y %H:%M:%S"),"subject": bp.subject}
            jsonfile = json.dumps(jsondict)
        #return jsonfile
        self.write(jsonfile)

class JSONBlogHander(MainHandler):
    def get(self):
        self.response.headers["Content-Type"] = "application/json"
        blogPosts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")
        jsonlist=[]
        for bp in blogPosts:
            jsondict = {"content": bp.content, "created": bp.created.strftime("%a, %d %b %Y %H:%M:%S"),"last_modified": bp.last_modified.strftime("%a, %d %b %Y %H:%M:%S"),"subject": bp.subject}
            jsonfile = json.dumps(jsondict)
            jsonlist.append(jsonfile)
        #return jsonlist
        self.write(jsonlist)

############## WIKI HANDLERS ########################################################
class EditHandler(MainHandler):
    def get(self, page_name):
        if not self.loggedin_user:
            self.redirect("/%s" %page_name)

        v = self.request.get("v") ## GETTING PARAMETERS FROM THE URL!!!!
        if v:
            wikipage = WikiPage.get_by_id(int(v))
        else:
            wikipage = db.GqlQuery("SELECT * FROM WikiPage WHERE page_name = '%s' ORDER BY last_modified DESC" %page_name).get();
        
        content = "";
        if wikipage:
            content = wikipage.content;
        self.render("editpage.html", content = content,page_name=page_name)

    def post(self, page_name):
        if not self.loggedin_user:
            self.redirect("/%s"%page_name)

        content = self.request.get("content")
        if content:
            wp = WikiPage(content=content, page_name=page_name)
            wp.put()
            #postID = wp.key().id()  # figure out permalinks!
            time.sleep(1)
            self.redirect("%s" % page_name)
        else:
            error = "we need some content!"
            self.render("editpage.html", content = content, error = error, page_name=page_name)

class WikiHandler(MainHandler):
    def get(self, page_name):
        v = self.request.get("v") ## GETTING PARAMETERS FROM THE URL!!!!
        if v:
            wikipage = WikiPage.get_by_id(int(v))
        else:
            wikipage = db.GqlQuery("SELECT * FROM WikiPage WHERE page_name = '%s' ORDER BY last_modified DESC" %page_name).get()
        user = self.loggedin_user
        if wikipage:
            self.render("displaypage.html", page_name = page_name, user = user, wikipage=wikipage)
        elif user:
            self.redirect("/_edit%s" % page_name)
        else:
            self.redirect("/login")

class HistoryHandler(MainHandler):
    def get(self, page_name):
        #self.response.out.write('history handler')
        wikipagelist = db.GqlQuery("SELECT * FROM WikiPage WHERE page_name = '%s' ORDER BY last_modified DESC" %page_name) #can also do order by created DESC limit 10
        wikipagelist = list(wikipagelist) #changes the cursor to a list, safer, prevent the running of multiple queries.
        user = self.loggedin_user
        self.render("history.html", page_name = page_name, user = user, wikipagelist=wikipagelist)
## FOR EVERY EDIT, CREATE A NEW ENTRY. when querying, sort by datetime.
###################################### END OF BLOG HANDLERS ########################
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout' +PAGE_RE, LogoutHandler),
                               ('/_edit' + PAGE_RE, EditHandler),
                               ('/_history' + PAGE_RE, HistoryHandler),
                               (PAGE_RE, WikiHandler),
                               ],
                              debug=True)

# app = webapp2.WSGIApplication([
#     webapp2.SimpleRoute(r'/blog/?', handler=MainHandler, name='blogfront'),
#     webapp2.SimpleRoute(r'/blog/?\.json', handler = JSONBlogHander, name='jsonblog'),
#     webapp2.SimpleRoute(r'/_edit/' + PAGE_RE, handler = EditHandler, name='edit'),
#     webapp2.SimpleRoute(PAGE_RE, handler = WikiHandler, name='wiki'),
#     routes.PathPrefixRoute(r'/blog', [
#         webapp2.Route(r'/newpost', handler = PostHandler, name='newpost'),
#         webapp2.Route(r'/<post_id:\d+>', handler = PermaLinkHandler, name='permpost'),
#         webapp2.Route(r'/<post_id:\d+><:\.json$>', handler = JSONHandler, name='jsonpost'),
#         webapp2.Route(r'/signup', handler = SignupHandler, name='signup'),
#         webapp2.Route(r'/welcome', handler = WelcomeHandler, name='welcome'),
#         webapp2.Route(r'/login', handler = LoginHandler, name='login'),
#         webapp2.Route(r'/logout', handler = LogoutHandler, name='logout'),
#         webapp2.Route(r'/flush', handler = FlushHandler, name='flush'),

#     ])
# ], debug=True)


#app = webapp2.WSGIApplication([
    #('/blog', MainHandler),
    #('/blog/newpost', PostHandler),
    #('/blog/(\d+)', PermaLinkHandler),
    #('/blog/(\d+).json', JSONHandler)
#], debug=True)

#https://webapp-improved.appspot.com/guide/routing.html URI routing