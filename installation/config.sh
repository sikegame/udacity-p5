#! /bin/bash

# 1. Update current repo and upgrade packages
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Install necessary Ubuntu packages
sudo apt-get install -y apache2 libapache2-mod-wsgi postgresql python-pip fail2ban python-psycopg2

# 3. Install Glances for monitoring
curl -L http://bit.ly/glances | /bin/bash

# 4. Install required Python modules
sudo pip install -r requirements.txt

# 5. Copy configuration files and restart Apache


# 6 Set password for Postgres account
sudo passwd postgres