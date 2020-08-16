import os

import webapp2
import jinja2

import boto3

os.environ['AWS_PROFILE'] = "Default"
os.environ['AWS_DEFAULT_REGION'] = "us-west-2"

from datetime import date
from datetime import datetime
import parse

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

import re
def valid_username(username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username and USER_RE.match(username)

def valid_password(password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

def valid_email(email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return not email or EMAIL_RE.match(email)

import random
import string
import hashlib

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    if make_pw_hash(name, pw, h.split(",")[1]) == h:
        return True

signupform="""
<h2>Signup</h2>
    <form method="post">
      <table>
        <tbody><tr>
          <td class="label">
            Username
          </td>
          <td>
            <input type="text" name="username" value="%(username)s">
          </td>
          <td class="error">
            %(username_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Password
          </td>
          <td>
            <input type="password" name="password" value="">
          </td>
          <td class="error">
            %(password_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Verify Password
          </td>
          <td>
            <input type="password" name="verify" value="">
          </td>
          <td class="error">
            %(verify_error)s
          </td>
        </tr>

        <tr>
          <td class="label">
            Email (optional)
          </td>
          <td>
            <input type="text" name="email" value="%(email)s">
          </td>
          <td class="error">
            %(email_error)s
          </td>
        </tr>
      </tbody></table>

      <input type="submit">
    </form>
"""

def create_post_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.client('dynamodb', region_name='us-west-2')
    try:
        table = dynamodb.create_table(
            TableName='Post',
           KeySchema=[
                {
                'AttributeName': 'permalink',
                'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'permalink',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        return table
    except dynamodb.exceptions.ResourceInUseException:
        pass
create_post_table()

def create_author_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.client('dynamodb', region_name='us-west-2')
    try:
        table = dynamodb.create_table(
            TableName='Author',
            KeySchema=[
                {
                    'AttributeName': 'username',
                    'KeyType': 'HASH'
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'username',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        return table
    except dynamodb.exceptions.ResourceInUseException:
        pass
create_author_table()

from boto3.dynamodb.conditions import Key
def scan_posts(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Post')
    scan_kwargs = {
        'ProjectionExpression': "title, subtitle, author, quod, cover, content, permalink"
    }

    done = False
    start_key = None
    l = []
    while not done:
        if start_key:
            scan_kwargs['ExclusiveStartKey'] = start_key
        response = table.scan(**scan_kwargs)
        l += response.get('Items', [])
        start_key = response.get('LastEvaluatedKey', None)
        done = start_key is None
    return l

def all_posts(update = False):
        #key = 'all'
        #posts = memcache.get(key)
        #if posts is None or update:
                #posts = db.GqlQuery("SELECT * FROM Post ORDER BY title DESC")
                #posts = list(posts)
        posts = scan_posts()
                #memcache.set(key, posts)
        return posts

from botocore.exceptions import ClientError
def get_post_table(dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Post')
    return table

def single_post(post_id, update=False, delete=False):
        #key = str(book_id)
        #if delete:
        #       memcache.delete(key)
        #else:
        #       book = memcache.get(key)
        #       if book is None or update:
        #               #book = Book.get_by_id(long(book_id))
        table = get_post_table()
        try:
            response = table.get_item(Key={'permalink': post_id[:-5]})
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            post = response['Item']
        #memcache.set(key, book)
        return post

class MainPage(webapp2.RequestHandler):
        def get(self):
            self.redirect("https://mindempathy.net/index")

class ContactPage(webapp2.RequestHandler):
        def get(self):
            self.redirect("https://mindempathy.net/contact")

# import urllib2, urllib
# from urllib2 import HTTPError
# import requests
import subprocess
import base64
class MailPHPPage(webapp2.RequestHandler):
        def post(self):
            # mydata = [('name', self.request.get('name')), ('email', self.request.get('email')), ('phone', self.request.get('phone')), ('message', self.request.get('message')), ('file[]', self.request.get('file[]'))]    #The first is the var name the second is the value
            # mydata = urllib.urlencode(mydata)
            # path = 'http://www.mindempathy.net/mail.php'    #the url you want to POST to
            # req = urllib2.Request(path, mydata)
            # req.add_header("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")
            # try:
            #     page = urllib2.urlopen(req)
            #     return webapp2.Response(page)
            # except HTTPError as e:
            #     content = e.read()
            # url = 'http://www.mindempathy.net/mail.php' 
            # data={'name': self.request.get('name'), 'email': self.request.get('email'), 'phone': self.request.get('phone'), 'message': self.request.get('message'), 'file[]': self.request.get('file[]')}
            # r = requests.post(url, data)
            # self.response.out(r.content)
            name = self.request.get('name')
            email = self.request.get('email')
            phone = self.request.get('phone')
            message = self.request.get('message')
            file = self.request.get('file[]')
            cmd = ['php mail.php "%s" "%s" "%s" "%s" "%s"'%(name, email, phone, message, base64.b64encode(file))]
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            return webapp2.Response(result.stdout.read())

class NewPostHandler(webapp2.RequestHandler):
        def get(self):
                self.redirect("https://mindempathy.net/new")

class EditPostHandler(webapp2.RequestHandler):
        def get(self, post_id):
                self.redirect("https://mindempathy.net/edit/"+post_id)

class SignupHandler(webapp2.RequestHandler):
        def get(self):
                self.redirect("https://mindempathy.net/signup")

def render_str(template, **params):
                t = jinja_env.get_template(template)
                return t.render(params)

class Handler(webapp2.RequestHandler):
        def write(self, *a, **kw):
                self.response.out.write(*a, **kw)
        def render_str(self, template, **params):
                return render_str(template, **params)
        def render(self, template, **kw):
                self.write(self.render_str(template, **kw))

class PermalinkHandler(Handler):
        def get(self, post_id):
                self.redirect("https://mindempathy.net/posts/"+post_id)

class LoginHandler(Handler):
        def get(self):
                self.redirect("https://mindempathy.net/login")

class LogoutHandler(Handler):
        def get(self):
                self.redirect("https://mindempathy.net/logout")

import mimetypes
class StaticFileHandler(webapp2.RequestHandler):
    def get(self, path):
        abs_path = os.path.abspath(os.path.join(self.app.config.get('webapp2_static.static_file_path', 'static'), path))
        if os.path.isdir(abs_path) or abs_path.find(os.getcwd()) != 0:
            self.response.set_status(403)
            return
        try:
            f = open(abs_path, 'r')
            self.response.headers.add_header('Content-Type', mimetypes.guess_type(abs_path)[0])
            self.response.headers['Content-Type'] = mimetypes.guess_type(abs_path)[0]
            self.response.out.write(f.read())
            f.close()
        except:
            self.response.set_status(404)

app = webapp2.WSGIApplication([
        ('/', MainPage),
        ('/index', MainPage),
        ('/contact', ContactPage),
        ('/mail.php', MailPHPPage),
        (r'/posts/(.+)', PermalinkHandler),
        (r'/edit/(.+)', EditPostHandler),
        ('/new', NewPostHandler),
        ('/login', LoginHandler),
        ('/logout', LogoutHandler),
        ('/signup', SignupHandler),
        (r'/static/(.+)', StaticFileHandler)
], debug = True)

def main():
    from paste import httpserver

    httpserver.serve(app, host='172.31.8.153', port='80')

if __name__ == '__main__':
    main()
