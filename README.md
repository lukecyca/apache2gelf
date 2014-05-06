apache2gelf
===========

A script to deliver Apache log files to graylog2 in GELF format over UDP.

Supports:
* Standard Apache error log format
* Standard Apache combined (or vhost_combined) access log;

Usage example
-------------

    <VirtualHost *:80>
      ServerName example.com
      DocumentRoot /var/www/example.com

      ErrorLog "|| /path/to/apache2gelf.py --format error --vhost example.com"
      CustomLog "|| /path/to/apache2gelf.py --format combined --vhost example.com" combined
    </VirtualHost>


Importing existing logs
-----------------------

    gunzip -c other_vhosts_access.log.9.gz | python apache2gelf.py --format vhost_combined


Command line parameters
-----------------------

* `--hostname` to specify a custom hostname
* `--server` to specify graylog2 server
* `--port` to specify graylog2 GELF port
* `--format` specify one of `combined`, `vhost_combined`, `error`
* `--vhost` to add an extra field called 'vhost' to all log messages. This allows you to configure per-virtualhost log handlers. If using `vhost_combined` access format, this will be overridden.

Credits
=======

Based off the original, Copyright (c) 2012, Anton Tolchanov
Modifications Copyright (c) 2014, Luke Cyca

The scripts are licensed under MIT license.

