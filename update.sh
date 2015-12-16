#! /bin/bash

git pull -u origin master
sudo apache2ctl restart
sudo service apache2 reload
