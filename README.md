# 2019-Python-jbro682
Author: Jonathan Browne

* A Client Webapp to run in a semi-distributed simple peer-to-peer social media network where many other client webapps communicate with one another
  to send messages to a locally client maintained chat log
* The system was semi-distributed because their was a central server provided that managed account/login details using public/private keys
* Originally run with 20-30 other webapps developed by a class of students

## Note
* This project will not function as intended given the central server originally provided is not running as well as there being no other clients to 
  communicate with
* It is possible to run the web client using the python shell and running 'main.py' however you will only be able to view an empty home page and the login
  screen and will not be able to login. If you do want to see this just open your browser of choice and enter 'localIpOfYourMachine:10050' 
  (e.g: 192.168.1.1:10050) as the URL.
* The main.py file which initializes the webapp was not written by me (Jonathan Browne) but was provided for the initial assignment. All work completed by
  me is in the 'server.py' file and all html files in the 'templates' folder
