README

------
Project 3: Multi-User Blog
Udacity Full Stack Web Development Nanodegree
Kirsten Meintjes
February 2017
------
Documents:
1) static
   - main.css
2) templates
   - base.html
   - frontpage.html
   - loginform.html
   - newpost.html
   - permalink.html
   - post.html
   - signupform.html
   - welcome.html
3) app.yaml
4) main.py
5) main.pyc
6) readme.md

------

Synopsis

This is the third of many projects completed for the Udacity Full Stack Web Development Nanodegree. The brief was to create a multi-user blog. This blog has the following functionality:
* users can sign up by creating a username and password (and optionally entering an email address)
* the app checks that the user does not already exist and there is a password verifier
* username and password are stored in the database (as provided by google app engine)
* there is a main blog page displaying the most recent 10 blog posts (most recent to least recent)
* users can create new posts
* new posts get posted to their own URL as determined by their unique post id in the database



Motivation

This project was created as per requirements of completion of the course.


Tests

Click on the provided link.


Installation

In order to run this project, you will need to have a working computer with a browser installed on it, as well as an internet connection in this case to click on the link to take you to the blog. 
If you want to open and edit the code, you will need a text reader - preferably a sophisticated one such as Sublime - and you'll need to download the files provided by me and open these with your text reader of choice. You will also need Google App Engine for Python installed; further information and the download instructions can be found here:
https://cloud.google.com/appengine/docs/standard/python/download

Once downloaded and installed, through your terminal you need to run a series of commands:
1) gcloud init --skip-diagnostics (then log in as yourself and log into the app)
2) cd (insert the address to your directory where the project files have been saved)
3) dev_appserver.py .
Now your project should be running on your local host, which can be seen when opening the browser and entering locahost:(insert port number). Mine is at localhost:8080


Contributors

Myself (Kirsten Meintjes)
Udacity

License

N/A

You need to add instructions on how to install the dependencies and run the app locally in your README.md file. Assume that your reader is unfamiliar with GAE and doesn't have it installed on their machine. What commands/steps what they need to successfully run your project on their machine?

