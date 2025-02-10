#!/bin/sh
chmod +x /etc/init.d/shadow
update-rc.d shadow defaults
/etc/init.d/shadow start
