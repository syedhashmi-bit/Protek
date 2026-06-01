# -----------------------------------------------------------------
# Protek MikroTik bouncer bootstrap — Arc 16 phase 94
#
# Paste this script into RouterOS terminal (Winbox → New Terminal,
# or `ssh router /import` from a file). Idempotent: re-running rotates
# the password and recreates the group with current perms.
#
# Creates:
#   - group `{{ group }}` with minimum perms for address-list ops
#   - user  `{{ username }}` in that group with a random 24-char password
#
# The address-list itself is created on demand by Protek; nothing here
# touches your firewall rules.
# -----------------------------------------------------------------

:local username "{{ username }}"
:local groupname "{{ group }}"
:local listname "{{ list_name }}"

:if ([:len [/user find name=$username]] > 0) do={
    :put ("[warn] user " . $username . " already exists — removing (active sessions will drop)")
    /user remove [find name=$username]
}
:if ([:len [/user group find name=$groupname]] > 0) do={
    :put ("[warn] group " . $groupname . " already exists — removing")
    /user group remove [find name=$groupname]
}

# Minimum perms for a CrowdSec bouncer:
#   api    — connect via 8728/8729
#   read   — list address-list entries
#   write  — add / remove entries
#   test   — required by some address-list operations on older v7
# Explicitly NOT granted: policy, password, sensitive, web, winbox,
# ftp, local, ssh, telnet, sniff, romon, dude, reboot.
/user group add name=$groupname \
    policy=api,read,write,test \
    comment="Protek CrowdSec bouncer (managed by '$listname' address-list)"

# Phase 98 — opt-in to the REST API on RouterOS v7. The `rest-api`
# policy doesn't exist on v6, so we try and swallow the error so v6
# routers still complete the bootstrap successfully.
:do {
    /user group set $groupname policy=api,read,write,test,rest-api
    :put "[info] rest-api policy enabled (RouterOS v7+ detected)"
} on-error={
    :put "[info] rest-api policy unavailable (RouterOS v6) — binary API only"
}

:local pwd [:rndstr length=24]
/user add name=$username group=$groupname password=$pwd \
    comment="Protek bouncer — minimum perms; rotate by re-running bootstrap"

:put "==============================================================="
:put "Protek bouncer user created."
:put ""
:put ("  Host        : <this router's IP> (visible via /ip address print)")
:put "  Port        : 8728  (plain API)  or  8729 (API-SSL)"
:put ("  Username    : " . $username)
:put ("  Password    : " . $pwd)
:put ("  Address list: " . $listname)
:put ""
:put "Now in the Protek UI:"
:put "  /bouncers/add → kind: mikrotik"
:put "  Paste the host / port / username / password / address-list."
:put ""
:put "Rotate credentials anytime by re-running this script — the"
:put "password changes; the address-list is untouched."
:put "==============================================================="
