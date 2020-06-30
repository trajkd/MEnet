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
            posts = all_posts()
            self.response.out.write(jinja_env.get_template('index.html').render(posts=posts))

class ContactPage(webapp2.RequestHandler):
        def get(self):
            self.response.out.write(jinja_env.get_template('contact.html').render())

import subprocess
class MailPHPPage(webapp2.RequestHandler):
        def get(self):
            self.response.out.write(jinja_env.get_template('mail.php').render())
        def post(self):
            subprocess.call("php ./mail.php")

class ConfigPHPPage(webapp2.RequestHandler):
        def get(self):
            self.response.out.write(jinja_env.get_template('config.php').render())

def query_authors(username, dynamodb=None):
    if not dynamodb:
        dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

    table = dynamodb.Table('Author')
    response = table.query(
        KeyConditionExpression=Key('username').eq(username)
    )
    return response['Items']

class NewPostHandler(webapp2.RequestHandler):
        def get(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_authors(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u[0]['password'].split(",")[0]==password_hash:
                                self.response.out.write(jinja_env.get_template('newpost.html').render(error="", title="", subtitle="", author="", content="", cover=""))
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')
        def post(self):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_authors(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u[0]['password'].split(",")[0]==password_hash:
                                if not self.request.get('title') or not self.request.get('title'):
                                        self.response.out.write(jinja_env.get_template('newpost.html').render(error="Title required!", title=self.request.get('title'), subtitle=self.request.get('subtitle'), author=self.request.get('author'), content=self.request.get('content'), cover=self.request.get('cover')))
                                        return
                                title = self.request.get('title')
                                posts = all_posts()
                                for post in posts:
                                        if post['title'] == title:
                                                self.response.out.write(jinja_env.get_template('newpost.html').render(error="Post with same title already added!", title=self.request.get('title'), subtitle=self.request.get('subtitle'), author=self.request.get('author'), content=self.request.get('content'), cover=self.request.get('cover')))
                                                return
                                dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
                                table = dynamodb.Table('Post')
                                table.put_item(
                                    Item={
                                        'title': self.request.get('title'),
                                        'subtitle': self.request.get('subtitle'),
                                        'author': self.request.get('author'),
                                        'quod': date.today().strftime("%B %d, %Y"),
                                        'content': self.request.get('content'),
                                        'cover': self.request.get('cover'),
                                        'permalink': parse.quote_plus(str(self.request.get('title')).lower())
                                    }
                                )
                                all_posts(True)
                                single_post(parse.quote_plus(str(self.request.get('title')).lower()), True)
                                self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

class EditPostHandler(webapp2.RequestHandler):
        def get(self, post_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_authors(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u[0]['password'].split(",")[0]==password_hash:
                                p = single_post(post_id)
                                self.response.out.write(jinja_env.get_template('editpost.html').render(post=p))
                        else:
                                self.redirect('/posts/'+post_id)
                else:
                        self.redirect('/posts/'+post_id)
        def post(self, post_id):
                userid_cookie = self.request.cookies.get("userid")
                if userid_cookie:
                        userid = userid_cookie.split("|")[0]
                        password_hash = userid_cookie.split("|")[1]
                        #u = User.get_by_id(long(userid))
                        u = query_authors(userid)
                        #if u != None and u.password.split(",")[0]==password_hash:
                        if u != None and u[0]['password'].split(",")[0]==password_hash:
                                #b = Book.get_by_id(long(book_id))
                                table = get_post_table()
                                if self.request.get('title') != '':
                                        response = table.update_item(
                                            Key={
                                                'permalink': post_id
                                            },
                                            UpdateExpression="set title=:t",
                                            ExpressionAttributeValues={
                                                ':t': self.request.get('title')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('subtitle') != '':
                                        response = table.update_item(
                                            Key={
                                                'permalink': post_id
                                            },
                                            UpdateExpression="set subtitle=:s",
                                            ExpressionAttributeValues={
                                                ':s': self.request.get('subtitle')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('author') != '':
                                        response = table.update_item(
                                            Key={
                                                'permalink': post_id
                                            },
                                            UpdateExpression="set author=:a",
                                            ExpressionAttributeValues={
                                                ':a': self.request.get('author')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('content') != '':
                                        #b.title = self.request.get('title')
                                        response = table.update_item(
                                            Key={
                                                'permalink': post_id
                                            },
                                            UpdateExpression="set content=:c",
                                            ExpressionAttributeValues={
                                                ':c': self.request.get('content')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                if self.request.get('cover') != '':
                                        #b.title = self.request.get('title')
                                        response = table.update_item(
                                            Key={
                                                'permalink': post_id
                                            },
                                            UpdateExpression="set cover=:v",
                                            ExpressionAttributeValues={
                                                ':v': self.request.get('cover')
                                            },
                                            ReturnValues="UPDATED_NEW"
                                        )
                                all_posts(True)
                                single_post(post_id, True)
                                self.redirect('/')
                        else:
                                self.redirect('/')
                else:
                        self.redirect('/')

class SignupHandler(webapp2.RequestHandler):
        def write_form(self, username="", email="", username_error="", password_error="", verify_error="", email_error=""):
                self.response.out.write(signupform%{"username": username,
                                                                                                "email": email,
                                                                                                "username_error": username_error,
                                                                                                "password_error": password_error,
                                                                                                "verify_error": verify_error,
                                                                                                "email_error": email_error})
        def get(self):
                self.write_form()
        def post(self, username="", email="", username_error="", password_error="", verify_error="", email_error="", ):
                username = self.request.get("username")
                password = self.request.get("password")
                verify = self.request.get("verify")
                email = self.request.get("email")
                if (valid_username(username) and valid_password(password) and valid_email(email) and password == verify):
                        #if len(db.Query(User).filter("username =", username).fetch(limit=1))==0:
                        if len(query_authors(username))==0:
                                password = make_pw_hash(username, password)
                                #u = User(username=username, password=password, email=email)
                                #u.put()
                                dynamodb = boto3.resource('dynamodb', region_name='us-west-2')
                                table = dynamodb.Table('Author')
                                table.put_item(
                                    Item={
                                        'username': username,
                                        'password': password,
                                        'email': email
                                    }
                                )
                                #self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u.key().id())+"|"+u.password))
                                self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(username+"|"+password))
                                self.redirect("/")
                        else:
                                self.write_form(username_error="That user already exists.")
                if not valid_username(username):
                        username_error = "That's not a valid username."
                if not valid_password(password):
                        password_error = "That's not a valid password."
                if not password == verify:
                        verify_error = "Your passwords didn't match."
                if not valid_email(email):
                        email_error = "That's not a valid email."
                self.write_form(username, email, username_error, password_error, verify_error, email_error)

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
                p = single_post(post_id)
                if not p:
                        self.error(404)
                        return
                self.render("permalink.html", post=p)

class LoginHandler(Handler):
        def get(self):
                self.render("login.html", username="", login_error="")
        def post(self):
                username = self.request.get("username")
                password = self.request.get("password")
                #u = db.Query(User).filter("username =", username).fetch(limit=1)
                u = query_authors(username)
                if not len(u)==0 and valid_pw(username, password, u[0]['password']):
                        #self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u[0].key().id())+"|"+str(u[0].password)))
                        self.response.headers.add_header("Set-Cookie", "userid=%s; Path=/"%(str(u[0]['username'])+"|"+str(u[0]['password'])))
                        self.redirect("/new")
                else:
                        self.render("login.html", username=username, login_error="Invalid login")

class LogoutHandler(Handler):
        def get(self):
                self.response.headers.add_header("Set-Cookie", "userid=; Path=/")
                self.redirect("/")

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
        ('/index.html', MainPage),
        ('/contact.html', ContactPage),
        ('/mail.php', MailPHPPage),
        ('/config.php', ConfigPHPPage),
        (r'/posts/(.+)', PermalinkHandler),
        (r'/(.+)/edit', EditPostHandler),
        ('/new', NewPostHandler),
        ('/login', LoginHandler),
        ('/logout', LogoutHandler),
        ('/signup', SignupHandler),
        (r'/static/(.+)', StaticFileHandler)
], debug = True)

def main():
    from paste import httpserver
    httpserver.serve(app, host='172.31.2.94', port='80')

if __name__ == '__main__':
    main()
