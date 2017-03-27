import os
import re

import random
import hashlib
import hmac

from string import letters

import webapp2
import jinja2

from google.appengine.ext import db 

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


"""Set up cookie and other external functions."""


secret = 'juicy'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    hashed = hmac.new(secret, val).hexdigest()
    return "%s|%s" % (val, hashed)

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


""" Handler class w/ fx to call into other classes."""


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):  # every request calls initialize
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)



"""USER SECURITY (Homework 3)"""


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt=h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


# Creates the user template

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())
        # in classmethods, return cls (not User/Object)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name, 
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


""" BLOG POSTS """   

# value of blog's parent
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Class 'template' for each blog post
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)  # not editable
    user_id = db.IntegerProperty()
    author = db.StringProperty()
    likes = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self)

# Front page of blog?
class BlogFront(BlogHandler):
    def get(self):
        # Access to ANY content only allowed if logged in
        if not self.user:
            return self.redirect('/login')

        posts = Post.all().order('-created')
        self.render('frontpage.html', posts=posts)

# Page for an individual post
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        # If someone looks for non-existant post
        if not post:
            return self.error(404)
            
        likes = Like.all().filter('post_id =', post_id)
        number = likes.count()

        comments = Comment.all().order('-created')
        self.render('permalink.html', post=post, comments=comments,
         likes=number, post_id=post_id)

# Function and load page for new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')

    def post(self):
        # another way of checking user (if vs if not)
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        # user_id = self.request.get('user_id')
        user_id = int(check_secure_val(self.request.cookies.get('user_id')))
        print "user ID for new post is: %s" % user_id
        likes = 0

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                author=author, likes=likes, user_id=user_id)
            p.put()  # creates instance in table?

            id = str(p.key().id())  
            # key is google app engines full representation of this object 
            # (.id turns it into an int)
            # now redirects to new unique permalink created for post
            self.redirect('/blog/%s' % id)

        else:
            error = "Enter both subject and content, please!"
            self.render('newpost.html', subject=subject, content=content,
                author=author, error=error)

# Function and load page to edit a post
class EditPost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user.name == post.author:
            self.render('editpost.html', post=post)

        else:  # Don't think this will be necessary, another check done before
               # offering the edit button (only option for the author)
            error = "You are not authorized to edit this post"
            self.render('editpost.html', error=error)
        
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user.name == post.author:
            subject=self.request.get('subject')
            content=self.request.get('content')

            if content and subject:
                key=db.Key.from_path('Post', int(post_id), parent=blog_key())
                post=db.get(key)
                # setting the edits
                post.subject=subject
                post.content=content
                post.put()

                self.redirect('/blog/%s' % post_id)
            else:
                error = "subject and content, please!"
                self.render('editpost.html', post=post, error=error)

                # self.render('editpost.html', subject=subject, content=content,
                #     author=author, error=error)  
                # I wonder if its best to pass in each of these parameters, 
                # or just post=post ?

        else:  # authorisation fails (can't only check in get)
            error = "You are not authorized to edit this post"
            return self.render('editpost.html', error=error)


# Function and load page to delete a post
class DeletePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user.name == post.author:
            self.render('deletepost.html', post=post)

        else:  
            self.redirect('/login')

       
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user.name == post.author:
            post.delete()
            self.redirect('/blog')

        else:
            self.redirect('/login')
            

"""POST LIKES"""


# Class 'template' for each like
class Like(db.Model):
    post_id = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)

# Logic for liking and unliking a post
class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.write("There is no post here to like!")

        # user cannot like their own post - first check this
        if self.user.name == post.author:
            return self.write("You cannot like your own post!")

        likes = Like.all()
        userid = check_secure_val(self.request.cookies.get('user_id'))

        flag = 0
        postlikes = 0

        for like in likes:
            if post_id == like.post_id:
                postlikes +=1
                if userid == like.user_id:  # check if user already liked post
                    flag +=1

        print "Flag value: %s" % flag
        print "Total likes on page value: %s" % postlikes

        if flag == 0:      # hasn't liked yet, so create new instance of like
            newlike = Like(parent=blog_key(), post_id=post_id, user_id=userid)
            newlike.put()
            post.likes = post.likes + 1
            print "created new like!"

        else:  # user has already liked post before, therefore must remove like
            like = Like.all().filter('post_id =', post_id).filter('user_id =', 
                userid).get()
            like.delete()

        self.redirect('/blog/%s' % str(post_id))

# Class 'template' for each comment
class Comment(db.Model, BlogHandler):
    author = db.StringProperty()
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str('comment.html', c=self)

# Function and load page for creating a new comment
class NewComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.write("There is no post!")
            return redirect('/blog')

        self.render('newcomment.html', post=post)

    def post(self, post_id):
        if not self.user:
            return redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.write("There is no post!")
            return redirect('/blog')

        comment = self.request.get('comment')
        author = self.user.name

        if comment:
            c = Comment(parent=blog_key(), comment=comment, author=author,
             post_id=post_id)
            c.put()

            self.redirect('/blog/%s' % post_id)

        else:
            error = "Please enter a comment!"
            self.render('newcomment.html', error=error, post=post)

# Function and load page for editing ones own comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        commentkey = db.Key.from_path('Comment', int(comment_id),
            parent=blog_key())
        comment = db.get(commentkey)

        content = comment.comment
        author = comment.author
        
        if comment and self.user.name == author:
            self.render('editcomment.html', post=post, comment=comment,
             author=author, content=content)
        else:
            return redirect('/blog')  
            # automatically redirects to login if issue is not logged in user

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        content = self.request.get('content')

        if content:
            commentkey = db.Key.from_path('Comment', int(comment_id),
             parent=blog_key())
            comment = db.get(commentkey)
            if self.user.name == comment.author:
                comment.comment = content
                comment.put()
                self.redirect('/blog/%s' % str(post_id))
            else:
                return redirect('/login')

        else:
            error = "Content for the comment, please!"
            self.render("editcomment.html", comment=comment, post=post,
             error=error)

# Function and load page for deleting ones own comment
class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        commentkey = db.Key.from_path('Comment', int(comment_id),
         parent=blog_key())
        comment = db.get(commentkey)

        if comment and self.user.name == comment.author:
            self.render('deletecomment.html', post=post, comment=comment)
        else:
            return redirect('/login')

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        commentkey = db.Key.from_path('Comment', int(comment_id),
         parent=blog_key())
        comment = db.get(commentkey)

        if comment and self.user.name == comment.author:
            comment.delete()
            self.redirect('/blog/%s'% post_id)
        else:
            return redirect('/blog')


""" SIGN UP (Homework 1) """


# It was suggested to me that these not be global variables
# but rather contained within singup class
# however I think this has caused bugs

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class SignUp(BlogHandler):
    def get(self):
        if self.user:
            return self.redirect('/blog')

        self.render('signupform.html')

    def post(self):
        haserror = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            haserror = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            haserror = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            haserror = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email"
            haserror = True

        # reloads signup form, keeps valid parameters (no passwords)
        if haserror:
            self.render('signupform.html', **params)
        else:
            self.done()

    def done(self):
        raise NotImplementedError  # Not sure what this is, just copied


class Register(SignUp):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists!"
            self.render('signupform.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        if self.user:
            return self.redirect('/blog')

        self.render('loginform.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')  

        else:
            msg = 'Invalid Login'
            self.render('loginform.html', error=msg)


class Logout(BlogHandler):  # a way to log out is to delete cookie
    def get(self):
        self.logout()
        self.render('logout.html')
    
# not sure if welcome class is working properly
# redirects are not going to /welcome
class Welcome(BlogHandler):
  def get(self):
    if not self.user:
        return self.redirect('/signup')

    username = self.user.name
    print "logged in - username retrieved for welcome class is %s" % username
    if valid_username(username):
        self.render('welcome.html', username=username)
    

class MainPage(BlogHandler):  # not sure if necessary
    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write('Hello, Blogging World!')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/blog/?', BlogFront),  # ? why not just /blog
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/([0-9]+)/edit', EditPost),
    ('/blog/([0-9]+)/delete', DeletePost),
    ('/blog/([0-9]+)/like', LikePost),
    #('/blog/([0-9]+)/deletelike', Deletelike),
    ('/blog/([0-9]+)/newcomment', NewComment),
    ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
