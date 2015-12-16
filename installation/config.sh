#! /bin/bash

# 1. Install necessary Ubuntu packages
sudo apt-get install -y apache2 libapache2-mod-wsgi postgresql python-pip fail2ban python-psycopg2

# 2. Install Glances for monitoring
curl -L http://bit.ly/glances | /bin/bash

# 3. Install required Python modules
sudo pip install -r requirements.txt

# 4. Copy configuration files and restart Apache
sudo cp /var/www/udacity-p5/installation/catalog.conf /etc/apache2/sites-enabled/catalog.conf
sudo a2ensite catalog.conf
sudo apache2ctl restart

# 5 Set password for Postgres account
sudo passwd postgres