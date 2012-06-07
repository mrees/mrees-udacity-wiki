# Udacity CS253 Homework 5
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


def top_posts(update = False):
  key = 'top_posts'
  posts = memcache.get(key)
  if posts is None or update:
    logging.error('db query')
    posts = db.GqlQuery('select * from BlogPost order by created desc limit 10')
    posts = list(posts)
    for post in posts:
      id = str(post.key().id())
      memcache.set(id, post)
      memcache.set('time ' + id, int(time.time()))
    memcache.set(key, posts)
    memcache.set('all-posts', str(int(time.time())))
  return posts
  
def get_post(id, update = False):
  post = memcache.get(id)
  if post is None or update:
    post = BlogPost.get_by_id(int(id))
    memcache.set(id, post)
    memcache.set('time ' + id, int(time.time()))
  return post, memcache.get('time ' + id)

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

class BlogPost(db.Model):
  subject = db.StringProperty(required=True)
  content = db.TextProperty(required=True)
  created = db.DateTimeProperty(auto_now_add=True)
  last_modified = db.DateTimeProperty(auto_now=True)

class UtilityHandler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    return render_str(template, **params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class NewPostHandler(UtilityHandler):
  def get(self):
    params = {}
    self.render('newpost.html', **params)
    
  def post(self):
    subject = self.request.get('subject')
    content = self.request.get('content')
    if not subject or not content:
      params = {'subject': subject, 'content': content,
        'errorMessage': 'Please provide both a title and post contents'}
      self.render('newpost.html', **params)
    else:
      post = BlogPost(subject=subject, content=content)
      post.put()
      top_posts(True)
      id = post.key().id()
      self.redirect('/' + str(id))
      
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
  return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
  return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
  return not email or EMAIL_RE.match(email)
    

class ShowPostHandler(UtilityHandler):
  def get(self):
    id = self.request.path[1:]
    post, cache_time = get_post(id)
    cache_time = int(time.time() - cache_time)
    if post:
      created = str(post.created)[0:16]
      last_modified = str(post.last_modified)[0:16]
      params = {'content': post.content, 
        'last_modified': last_modified,
        'subject': post.subject,
        'created': created,
        'id': id,
        'cache_time': cache_time}
      self.render('showpost.html', **params)
    else:
      self.redirect('/')
		
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
    
class WelcomeHandler(UtilityHandler):
  def get(self):
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      user = User.get_by_id(int(userhash.split('|')[0]))
      params = dict(username=user.username)
      self.render("welcome.html", **params)
    else:
      self.redirect('/signup')

class JsonHandler(UtilityHandler):
  def get(self):
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      id = self.request.path[1:].split('.')[0]
      self.response.headers.add_header('Content-Type', 'application/json')
      post = BlogPost.get_by_id(int(id))
      if post:
        p = {'subject': post.subject, 'content': post.content, 
              'created': post.created.strftime("%a %b %d %H:%M:%S %Y"), 
              'last_modified': post.last_modified.strftime("%a %b %d %H:%M:%S %Y")}
        self.write(json.dumps(p))
      else:
        self.write(json.dumps({}))
    else:
      self.redirect('/login')

class AllJsonHandler(UtilityHandler):
  def get(self):
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      self.response.headers.add_header('Content-Type', 'application/json')
      allposts = db.GqlQuery('select * from BlogPost order by created')
      allpostslist = []
      for post in allposts:
        p = {'subject': post.subject, 'content': post.content, 
              'created': post.created.strftime("%a %b %d %H:%M:%S %Y"), 
              'last_modified': post.last_modified.strftime("%a %b %d %H:%M:%S %Y")}
        allpostslist.append(p)
      self.write(json.dumps({'posts': allpostslist}))
    else:
      self.redirect('/login')
      
class FlushHandler(UtilityHandler):
  def get(self):
    memcache.flush_all()
    top_posts(True)
    self.redirect('/')

class MainHandler(UtilityHandler):
  def get(self):
    userhash = self.request.cookies.get('user_id', '')
    if check_secure_val(userhash):
      user = User.get_by_id(int(userhash.split('|')[0]))
      username=user.username
    else:
      username = 'grader'
    posts = top_posts()
    all_posts_time = int(time.time()) - int(memcache.get('all-posts'))
    params = {'posts': posts, 'username': username, 'all_posts_time': all_posts_time}
    self.render('blogposts.html', **params)
    # else:
      # self.redirect('/login')
      

app = webapp2.WSGIApplication([
  ('/', MainHandler),
  ('/.json', AllJsonHandler),
  ('/signup', SignupHandler),
  ('/welcome', WelcomeHandler),
  ('/login', LoginHandler),
  ('/logout', LogoutHandler),
  ('/newpost', NewPostHandler),
  ('/[0-9]+', ShowPostHandler),
  ('/[0-9]+.json', JsonHandler),
  ('/flush', FlushHandler)
  ],
  debug=True)
