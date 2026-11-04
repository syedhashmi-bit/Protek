# -----------------------------------------------------------------
# Protek: drop traffic from the "{{ list_name }}" address list{% if v6_only %} (IPv6)
#
# Your IPv4 rules already drop this list; this adds the missing IPv6 rule.{% endif %}
#
# Paste into the RouterOS terminal (Winbox → New Terminal). Safe to
# re-run: an existing rule is enabled rather than duplicated.
#
# The rule goes in the raw table's prerouting chain, first in line.
# Prerouting sees every packet arriving from the internet — traffic
# to the router itself AND traffic forwarded to your network — and
# raw runs before connection tracking, so it's also the cheapest place
# to drop.
#
# Before pasting: put your own IPs on Protek's whitelist (Rules →
# Whitelist). If CrowdSec ever bans you, this rule drops you too.
# -----------------------------------------------------------------

:local listname "{{ list_name }}"

{% if not v6_only %}
/ip firewall raw enable [find chain=prerouting src-address-list=$listname action=drop disabled=yes]
:if ([:len [/ip firewall raw find chain=prerouting src-address-list=$listname action=drop]] = 0) do={
    :if ([:len [/ip firewall raw find]] = 0) do={
        /ip firewall raw add chain=prerouting src-address-list=$listname action=drop \
            comment="protek: drop CrowdSec bans"
    } else={
        /ip firewall raw add chain=prerouting src-address-list=$listname action=drop \
            comment="protek: drop CrowdSec bans" place-before=[:pick [/ip firewall raw find] 0]
    }
    :put "[ok] IPv4 drop rule added"
} else={
    :put "[ok] IPv4 drop rule present"
}

{% endif %}
:do {
    /ipv6 firewall raw enable [find chain=prerouting src-address-list=$listname action=drop disabled=yes]
    :if ([:len [/ipv6 firewall raw find chain=prerouting src-address-list=$listname action=drop]] = 0) do={
        :if ([:len [/ipv6 firewall raw find]] = 0) do={
            /ipv6 firewall raw add chain=prerouting src-address-list=$listname action=drop \
                comment="protek: drop CrowdSec bans (IPv6)"
        } else={
            /ipv6 firewall raw add chain=prerouting src-address-list=$listname action=drop \
                comment="protek: drop CrowdSec bans (IPv6)" place-before=[:pick [/ipv6 firewall raw find] 0]
        }
        :put "[ok] IPv6 drop rule added"
    } else={
        :put "[ok] IPv6 drop rule present"
    }
} on-error={
    :put "[info] no IPv6 firewall on this router — skipped"
}
