#! /bin/bash

sudo cat /var/log/apache2/error.log
sudo truncate -s 0 /var/log/apache2/error.log
