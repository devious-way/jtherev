# jtherev
John The Revealer: Check an IP address through multiple DNS-based blacklists (DNSBL) and IP reputation services in real-time. In this way, you'll be able to detect if an IP is involved in malware incidents and spamming activities.

![John](https://github.com/deviousway/jtherev/blob/master/title.PNG)

## Installation (GNU/LINUX):
```
git clone https://github.com/deviousway/jtherev/
cd jtherev/
pip install -r requirements.txt
```

### How does it work?
**Input**: enter the IPv4 address you want to check.
In the following, *jtherev* will start in complete autonomy, intentionally to give a complete overview of automated analysis using open source resources. There are exactly three stages that will follow:
1. Geo IP Location;
2. DNSBL Check and a final summary of the blacklists that were found for that IP address.
3. TOR exit node check.
