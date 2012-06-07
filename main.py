# Udacity CS253 Homework 7 - Wiki
#

import os
import webapp2
import sys
import jinja2
import re
import hashlib
import hmac
import string
import random
import json
import logging
import time

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
  t = jinja_env.get_template(template)
  return t.render(params)
  
def get_page(pagename):
  pages = db.GqlQuery("select * from WikiPage where pagename = '" + pagename + "'")
  if pages.count() == 0:
    page = None
  else:
    page = pages[0]
  return page

SECRET = 'michaelrees'
def hash_str(s):
  return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
  return "%s|%s" % (s, hash_str(s))
  
def check_secure_val(h):
  val = h.split('|')[0]
  if h == make_secure_val(val):
    return val

def make_salt():
  return ''.join(random.choice(string.letters) for x in xrange(5))
  
def make_pw_hash(name, pw, salt=None):
  if not salt:
    salt = make_salt()
  return hashlib.sha256(name + pw + salt).hexdigest() + ',' + salt
  
def valid_pw(name, pw, h):
  salt = h.split(',')[1]
  return h == make_pw_hash(name, pw, salt)
  
class User(db.Model):
  username = db.StringProperty(required=True)
  password = db.StringProperty(required=True)
  email = db.StringProperty()

class WikiPage(db.Model):
  pagename = db.StringProperty(required=True)
  contents = db.TextProperty()
  created = db.DateTimeProperty(auto_now_add=True)
  last_modified = db.DateTimeProperty(auto_now=True)

class UtilityHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    return render_str(template, **params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))
      
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
  return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
  return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
  return not email or EMAIL_RE.match(email)
    		
class SignupHandler(UtilityHandler):
  def get(self):
    self.render("signup.html")
    
  def post(self):
    have_error = False
    username = self.request.get('username')
    password = self.request.get('password')
    verify = self.request.get('verify')
    email = self.request.get('email')

    params = dict(username = username,
                  email = email)

    if not valid_username(username):
      params['error_username'] = "That's not a valid username."
      have_error = True

    if not valid_password(password):
      params['error_password'] = "That wasn't a valid password."
      have_error = True
    elif password != verify:
      params['error_verify'] = "Your passwords didn't match."
      have_error = True

    if not valid_email(email):
      params['error_email'] = "That's not a valid email."
      have_error = True

    if have_error:
      self.render('signup.html', **params)
    else:  
      users = db.GqlQuery("select * from User where username = '" + username + "'")
      usersfound = users.count()
      if usersfound > 0:
        params['error_username'] = "User name already in use"
        self.render('signup.html', **params)
      else:
        newuser = User(username=username, password=make_pw_hash(username, password), email=email)
        newuser.put()
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' 
          % make_secure_val(str(newuser.key().id())))
        self.redirect('/')
        
class LoginHandler(UtilityHandler):
  def get(self):
    self.render('login.html')
    
  def post(self):
    have_error = False
    username = self.request.get('username')
    password = self.request.get('password')
    params = dict(username=username)
    if not valid_username(username):
      params['error_username'] = "That's not a valid username."
      have_error = True
    if not valid_password(password):
      params['error_password'] = "That wasn't a valid password."
      have_error = True
    if have_error:
      self.render('login.html', **params)
    else:
      users = db.GqlQuery("select * from User where username = '" + username + "'")
      usersfound = users.count()
      if usersfound > 0:
        pwhash = users[0].password
        if valid_pw(username, password, pwhash):
          self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' 
            % make_secure_val(str(users[0].key().id())))
          self.redirect('/')
        else:
          params['error_password'] = "Invalid password"
          self.render('login.html', **params)
      else:
        params['error_username'] = "User name not found"
        self.render('login.html', **params)

class LogoutHandler(UtilityHandler):
  def get(self):
    self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
    self.redirect('/')

class WikiPageHandler(UtilityHandler):
  def get(self, path):
    username = None
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      user = User.get_by_id(int(userhash.split('|')[0]))
      username = user.username
    pagename = path
    page = get_page(pagename)
    if not page and not username:
      self.redirect('/signup')
      return
    if not page and username:
      self.redirect('/_edit' + path)
    elif page: 
      params = {'username': username, 'pagename': pagename,
          'contents': page.contents}
      self.render('wikipage.html', **params)

class EditPageHandler(UtilityHandler):
  def get(self, path):
    username = None
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      user = User.get_by_id(int(userhash.split('|')[0]))
      username = user.username
    pagename = path
    page = get_page(pagename)
    if page is None and username:
      page = WikiPage(pagename=pagename, contents='')
      page.put()
      logging.error('just put page: ' + str(page.pagename))
    if not page is None and username:
      params = {'pagename': page.pagename, 'contents': page.contents, 'username': username}
      self.render('editpage.html', **params)
    elif page:
      self.redirect(path)
    else:
      self.redirect('/signup')
    
  def post(self, path):
    username = None
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      user = User.get_by_id(int(userhash.split('|')[0]))
      username = user.username
    pagename = path
    page = get_page(pagename)
    if page is None and username:
      page = WikiPage(pagename=pagename, contents='')
      page.put()
      logging.error('just put page: ' + str(page.pagename))
    page.contents = self.request.get('content')
    page.put()
    self.redirect(pagename)
    
class Testing(UtilityHandler):
  def get(self):
    self.write('root')
     
      
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
  ('/signup', SignupHandler),
  ('/login', LoginHandler),
  ('/logout', LogoutHandler),
  ('/_edit' + PAGE_RE, EditPageHandler),
  (PAGE_RE, WikiPageHandler),
  ],
  debug=True)
