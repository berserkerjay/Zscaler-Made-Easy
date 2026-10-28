"""A fake tenant for the ZIA modules the Path analyzer walks (Advanced
Threat Protection, Cloud Firewall, DNS Control, Sandbox), on top of the
Data Flow fake. Field names follow zscaler-sdk-python 1.11.3's models."""
from __future__ import annotations

ATP_SETTINGS = {"riskTolerance": 40, "malwareSitesBlocked": True, "knownPhishingSitesBlocked": True,
                "cryptoMiningBlocked": False, "blockedCountries": []}
FIREWALL_RULES = [
    {"id": 1, "name": "Block QUIC", "order": 1, "state": "ENABLED", "action": "BLOCK_DROP", "nwServices": [{"id": 10, "name": "QUIC"}]},
    {"id": 2, "name": "Block SSH to bad nets", "order": 2, "state": "ENABLED", "action": "BLOCK_RESET",
     "nwServiceGroups": [{"id": 20, "name": "Remote access"}], "destIpGroups": [{"id": 30, "name": "Bad nets"}]},
    {"id": 3, "name": "Allow web", "order": 3, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 11, "name": "HTTP"}, {"id": 12, "name": "HTTPS"}]},
    {"id": 4, "name": "Office hours RDP", "order": 4, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 13, "name": "RDP"}],
     "timeWindows": [{"id": 1, "name": "Work hours"}]},
    {"id": 6, "name": "Allow all web (later)", "order": 6, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 12, "name": "HTTPS"}]},
    {"id": 7, "name": "Old disabled rule", "order": 7, "state": "DISABLED", "action": "ALLOW"},
    {"id": 5, "name": "Default Firewall Filtering Rule", "order": -1, "defaultRule": True, "predefined": True, "state": "ENABLED", "action": "BLOCK_DROP"},
]
NETWORK_SERVICES = [
    {"id": 10, "name": "QUIC", "tag": "QUIC", "destUdpPorts": [{"start": 443}]},
    {"id": 11, "name": "HTTP", "tag": "HTTP", "destTcpPorts": [{"start": 80}]},
    {"id": 12, "name": "HTTPS", "tag": "HTTPS", "destTcpPorts": [{"start": 443}]},
    {"id": 13, "name": "RDP", "tag": "RDP", "destTcpPorts": [{"start": 3389}], "destUdpPorts": [{"start": 3389}]},
    {"id": 14, "name": "SSH", "tag": "SSH", "destTcpPorts": [{"start": 22}]},
]
DNS_RULES = [
    {"id": 1, "name": "Block gambling lookups", "order": 1, "state": "ENABLED", "action": "BLOCK", "destIpCategories": ["GAMBLING"]},
    {"id": 2, "name": "Default DNS rule", "order": -1, "defaultRule": True, "state": "ENABLED", "action": "ALLOW"},
]
SANDBOX_RULES = [
    {"id": 1, "name": "Quarantine unknown executables", "order": 1, "state": "ENABLED", "baRuleAction": "BLOCK", "firstTimeEnable": True,
     "firstTimeOperation": "QUARANTINE", "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"], "protocols": ["HTTPS_RULE", "HTTP_RULE"]},
]

MODULE_ROUTES = {
    "/zia/cyberThreatProtection/advancedThreatSettings": ATP_SETTINGS,
    "/zia/cyberThreatProtection/securityExceptions": {"bypassUrls": ["trusted.example"]},
    "/zia/cyberThreatProtection/maliciousUrls": {"maliciousUrls": ["bad.example", "files.example/payload"]},
    "/zia/security": {"whitelistUrls": []},
    "/zia/security/advanced": {"blacklistUrls": [".blocked-domain.example"]},
    "/zia/firewallFilteringRules": FIREWALL_RULES,
    "/zia/networkServices": NETWORK_SERVICES,
    "/zia/networkServiceGroups": [{"id": 20, "name": "Remote access", "services": [{"id": 14, "name": "SSH"}]}],
    "/zia/networkApplicationGroups": [],
    "/zia/ipDestinationGroups": [{"id": 30, "name": "Bad nets", "type": "DSTN_IP", "addresses": ["198.51.100.0/24"]}],
    "/zia/ipSourceGroups": [],
    "/zia/firewallDnsRules": DNS_RULES,
    "/zia/sandboxRules": SANDBOX_RULES,
}
