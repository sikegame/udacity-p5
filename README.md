<h1>Product Catalog App</h1>

## Synopsis

This is a simple web-based product catalog with the social media user authentication system. Users can connect their credentials through Facebook, Google and GitHub account.

## Features

- JSON/XML/RSS API endpoints
- oAuth2 user authentication with Facebook, Google, Github
- CSRF protection
- File upload function
- Create, modify, delete categories
- User-friendly bootstrap interface

## Requirements

- Python 2.7
- Flask version 0.9
- SQL Alchemy
- Google oAuth 2.0
- Httplib2
- Werkzung WSGI utility library
- dict2xml library
- Flask-SeaSurf library

## For Udacity Reviewer

- IP: 52.34.152.224
- Port: 2200
- URL: http://ec2-52-34-152-224.us-west-2.compute.amazonaws.com

I have installed Apache (with WSGI mod), Flask, PostgreSQL, and other dependencies. UFW firewall has been configured, and Fail2Ban will block any unsuccessful login attempts. The server will be monitored by Glances as well.

## Installation

1. Update repo and install GIT software
    - Run `sudo apt-get update`
    - Run `sudo apt-get upgrade -y`
    - Run `sudo apt-get install -y git`
2. Create a folder to store this web app
    - Run `cd /var/www`
    - Run `git clone https://github.com/sikegame/udacity-p5.git`
    - You may need to play with file/folder permissions
3. Move to Catalog App folder
    - Run `cd udacity-p5/installation`
    - Run `. config.sh`
    - This script will install all the necessary packages and modules
    - Once the process finishes, it will prompt to set password for Postgres account
4. Configure Postgres Database
    - Run `su postgres`
    - Enter password for postgres account
    - Run `psql`
    - Run `\i /var/www/udacity-p5/installation/catalog.sql`
    - Run `\q`
    - Run 'exit'
5. Restart Postgres service
    - Run `sudo service postgresql restart`
6. Open your browser and access http://ec2-52-34-152-224.us-west-2.compute.amazonaws.com

## Extra works

- Cron script is placed on `/etc/cron.weekly/autoupdt` to automatically update packages weekly
- Glances has been installed to monitor server status
- Fail2Ban has been installed to block repeated unsuccessful login attempts

## Screenshot

![Homepage](/screenshot.jpg)

## Category Operation

`/add/category`

Add a new category. A user must be logged in.

`/edit/category/CATEGORY_ID`

Modify an existing category. A user must be logged in and has to be the creator of the category.

`/delete/category/CATEGORY_ID`

Delete an existing category. A user must be logged in and has to be the creator of the category.

## Product Operation

`/add/product`

Add a new product. A user must be logged in.

`/edit/product/PRODUCT_ID`

Modify an existing product. A user must be logged in and has to be the creator of the product page.

`/delete/product/PRODUCT_ID`

Delete an existing product. A user must be logged in and has to be the creator of the product page.

## API endpoints

`/json`

Returns the list of all products in JSON format.

`/xml`

Returns the list of all products in XML format.

`/feed`

Returns the most recent five products in XML format for RSS feed.

## Contacts

Please send any bug reports or feedbacks to

Email: no_real_email_address@gmail.com