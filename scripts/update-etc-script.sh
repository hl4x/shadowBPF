#!/bin/sh
chmod +x /etc/init.d/shadow_startup
update-rc.d shadow_startup defaults
/etc/init.d/shadow_startup start
