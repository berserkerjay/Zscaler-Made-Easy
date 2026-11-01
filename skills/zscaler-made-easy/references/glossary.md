# Plain-word glossary

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

The words the app's Simple mode explains, re-authored here so an answer can
use the same plain words the admin sees in the app. Use them when the admin
is new to Zscaler or asks "what does that mean?"; keep the technical word
in the answer and add its plain meaning once.

Source: the app's Simple mode glossary (`static/glossary.js`); when a word
there is added or changed, this file is updated with it (a test checks that
every word there is here).

| Word | In plain words |
|---|---|
| access policy | The access policy is the list of ZPA rules that say who may open which private app. If no rule allows it, ZPA says no. |
| access rule | An access rule says who may reach which private apps. The first rule that fits decides. |
| access token | An access token is a short pass Zscaler gives this app when it signs in. It lists what the app may use. The app shows what it says, but never keeps it. |
| activate | Activate means switch saved changes on in Zscaler. Until then, they wait. |
| Advanced Threat Protection | Advanced Threat Protection blocks sites known to be bad, like fake login pages. It also has lists of sites to always block or always let through. |
| AI Guard | AI Guard is a Zscaler service that reads what people type into AI chat apps and what the apps answer. It can warn or stop when private data is in it. |
| allowed but blockable | Allowed but blockable means a site gets through today. A rule could block it, but that rule is only for some people or places. |
| API | An API is a door that lets one program talk to another. This app uses it to read your settings. |
| API client | An API client is a login made just for an app. It has its own ID and its own secret. |
| API role | An API role is the set of things an API client may do. An admin picks it. It can let the app look, change things, or do nothing. |
| App Connector | An App Connector is a small Zscaler program that sits next to your private apps. It carries the traffic to them. |
| app profile | An app profile holds the settings Client Connector uses on a computer. Each group of people can get a different one. |
| app segment | An app segment is a list of names and ports for one private app. ZPA uses it to know which app you want. |
| baseline | A baseline is a starting set of safe rules. You check it, then turn the rules on one by one. |
| block | Block means Zscaler stops the action. The person sees a page that says why. |
| Browser Access | Browser Access lets people open a work web app from any browser. They do not need the Zscaler app on that computer. |
| browser isolation | Browser isolation opens a website on a Zscaler computer, not on yours. You only see a picture of the page, so files and bad code stay away. |
| Business Insights | Business Insights makes reports from web traffic. They show which apps people use, and how much. |
| bypass | A bypass lets traffic skip Zscaler. Zscaler cannot check what it cannot see. |
| catch-all rule | A catch-all rule matches all traffic the rules above it did not. It must stay at the bottom. |
| caution page | A caution page warns you before you go to a site. You can read it and then choose to go on. |
| certificate pinning | Some apps only trust their own lock. When Zscaler opens their traffic, they stop working. We say they pin their certificate. |
| channel | A channel is a road data can take, like the web, email or a cloud app. |
| check-up | A check-up looks at your settings one by one. It ends with a score and a list of things to fix. |
| Client Connector | Client Connector is the Zscaler app on each computer. It sends the web traffic of that computer to Zscaler. |
| client forwarding policy | The client forwarding policy tells Client Connector whether to send a private app to ZPA or let it go another way. |
| client ID | The client ID is like a user name for this app. You get it in ZIdentity. |
| client secret | The client secret is like a password for this app. Keep it safe and never share it. |
| cloud | The cloud is the group of Zscaler computers your company uses. Most companies use the main one. |
| Cloud & Branch Connector | A Cloud or Branch Connector sends the traffic of servers and offices to Zscaler, the way Client Connector does for a computer. |
| Cloud App Control | Cloud App Control sets what people can do in web apps. For example, it can stop uploads to a file drive. |
| Cloud Firewall | The Cloud Firewall checks all traffic, not just the web. Its rules allow or block by port, address and app. |
| CloudPath probe | A CloudPath probe follows the road from a computer to an app. It shows which stop on the way is slow. |
| compliance | Compliance means you follow the rules a law asks for. FedRAMP and HIPAA are two of them. |
| compliance overlay | An overlay adds the rules of a law or standard, like HIPAA, to each rule it fits. It shows why each rule is there. |
| conditional | A conditional result could change with things this app cannot check, like the time of day or who the user is. |
| connector group | A connector group is a team of App Connectors in one place. Two or more keep an app up if one stops. |
| coverage | Coverage is how many checks could run. If the app was not let in to look, that check is not in the score. |
| custom URL category | A custom URL category is your own list of sites. A rule can block or allow the whole list at once. |
| decrypt | To decrypt is to unlock traffic so Zscaler can read it. Then it is locked again on its way. |
| department | A department is a team in your company, like Sales or Finance. A rule can name a department to act only on its people. |
| deploy | Deploy means put new rules into your Zscaler. It only happens after you say yes. |
| detection policy | A detection policy is the list of things AI Guard looks for, like card numbers or tricks against the AI. |
| device posture | Device posture is a health check on a computer or phone. It asks things like: is it a work device, and is its guard app on? |
| device trust level | The device trust level says how much Zscaler trusts a computer: low, medium or high. A rule can act only on some levels. |
| dictionary | A dictionary is a list of words and number shapes to look for. One might look for card numbers. |
| DLP | DLP stands for data loss prevention. It stops private data from leaving your company by mistake. |
| DNS Control | Before a computer visits a site, it asks for the address of the name. DNS Control can block or change that answer. |
| domain-joined | A domain-joined computer is one your company set up and controls. Home computers are not. |
| drift | Drift is when a setting you said yes to changes back on its own, or someone changes it. A rule that was on is now off. |
| EASM | EASM scans what the company shows on the internet. It lists the weak spots it finds there. |
| EDR | EDR is a guard app on each computer. It watches for bad programs and stops them. |
| encrypted | Encrypted means locked with a secret code. Only the right key can open it. |
| endpoint | An endpoint is a computer or phone that people use. Endpoint rules work right on the device. |
| engine | An engine mixes word lists into one test. It decides when a match is big enough to count. |
| engine expression | An engine expression is the test inside an engine. It says how many matches of each word list are needed. |
| expert view | The expert view is the full tool with every page and choice. It is made for people who know Zscaler well. |
| file type | A file type is a kind of file, like a Word file or a program. Rules can allow or block some kinds. |
| finding | A finding is one thing the check-up noticed. Some are fine and some need a fix. |
| forwarding profile | A forwarding profile tells Client Connector how to send traffic to Zscaler. It can differ at the office and at home. |
| framework file | A framework file is a saved copy of web rules from one tenant. You can load it to build the same rules in another. |
| glass effect | The glass effect makes bars, cards and buttons see-through, like frosted glass. You can turn it off in Advanced settings. |
| heal | Heal puts a drifted setting back the way you said yes to. It only happens when you click Heal and type the safety words. |
| incident | An incident is a note that a rule found something. It says who, what and where. |
| incident receiver | The incident receiver gets a copy of what a DLP rule caught. It puts it where Workflow Automation can see it. |
| inspected | Inspected traffic has been opened and checked by Zscaler. DLP can only check what is inspected. |
| intermediate certificate | Zscaler uses this certificate to open locked web traffic. Your computers must trust it, or sites show a warning. |
| IP group | An IP group is a list of addresses you make in Zscaler. A firewall rule can name the group to block or allow them all. |
| licence | A licence is a part of Zscaler your company pays for. If a part is not on the list, its rules will not work. |
| location | A location is an office or site that sends its traffic to Zscaler. Rules can name a location to act only there. |
| location group | A location group puts many locations in one bag. A rule can name the group instead of each site. |
| Microsegmentation | Each server gets a small Zscaler agent. A server may only talk to the servers a rule names. So an attacker is stuck on one server. |
| monitor-only | Monitor-only means a rule just watches and writes down what it saw. It does not stop anyone. |
| negated condition | A negated condition is a check turned upside down. It matches when the thing is not true. |
| PAC file | A PAC file is a small list your browser reads. It says which sites go through Zscaler and which go around it. |
| packet | A packet is a small piece of traffic. The moving dots in a picture show packets on their way. |
| Path analyzer | The Path analyzer follows one website visit step by step. It shows what lets it through and what stops it. |
| policy | A policy is a set of rules. It says what is allowed and what is not. |
| policy pack | A policy pack is a ready-made set of word lists, engines and rules. It saves you days of work. |
| policy token | A policy token is a code in the install command. It tells a new Client Connector which app profile to use. Keep it private. |
| port | A port is a number that says which service traffic is for. Web pages use 443, and a remote desktop uses 3389. |
| portal default | The portal default is the value a setting has when you make a new profile and change nothing. |
| POV | A POV is a proof of value. The customer tries Zscaler for a few weeks to see that it does what they need. |
| predefined app | A predefined app is one Zscaler already knows, like Microsoft 365 or Zoom. Zscaler sets up its tests for you. |
| prefix | A prefix is a short tag at the start of a name, like pov1. The builder puts it on all it makes, so it can find them again. |
| preflight | Preflight is a practice run. It shows what would change, but it changes nothing. |
| Privileged Remote Access | Privileged Remote Access lets admins reach a server through a web page. Nobody needs a VPN, and the server stays hidden. |
| probe | A probe is a small test the Zscaler app runs on each computer, again and again. ZDX uses the results to show what is slow. |
| projected score | A projected score is your score after the fixes you pick. It is a guess made with the real math, before you change a thing. |
| provisioning key | A provisioning key is a one-time code. A new App Connector uses it to join its connector group. Keep it secret. |
| proxy chaining | Proxy chaining means Zscaler passes some traffic on to a second checker before it goes out. Here the second checker is AI Guard. |
| proxy gateway | A proxy gateway tells Zscaler which proxy to pass traffic to. You make it in the Zscaler portal, not in this app. |
| quality score | The quality score shows how well this app itself is tested. It goes from 0 to 100. Open problems pull it down. |
| QUIC | QUIC is a fast way to load web pages that uses UDP on port 443. Zscaler cannot look inside it, so many companies block it. |
| read-only | Read-only means the app can look but not touch. Nothing in your Zscaler changes. |
| readiness check | The readiness check looks at what this app may do, right after you sign in. It greys out what will not work and says what to ask for. |
| rule | A rule says what to do when an engine finds a match. It can watch, ask, or block. |
| rule walk | A rule walk shows one web request meeting the SSL rules in order. The first rule that fits decides what happens to it. |
| runbook | A runbook is a list of tests with the steps for each one. You follow it and write down what happened. |
| SaaS | SaaS means apps you use in a web browser, like Box or Google Drive. Zscaler can check the files kept there. |
| safety words | The safety words are YES_I_UNDERSTAND. You type them to show you really mean to allow changes. |
| sample tenant | The sample tenant is a made-up company. You can try every part of the app on it, and nothing you do touches a real one. |
| Sandbox | The Sandbox runs a new file on a Zscaler computer to see what it does. A bad file is stopped before it reaches you. |
| saved connection | A saved connection keeps the details for one company. Next time, you do not need to type them again. |
| scope | Scope is what you let the app look at. It reads nothing outside of it. |
| score | The score shows how well your settings follow good advice. Higher is better, and 100 is the top. |
| score drop | A score drop means your score went down since last time. The app shows which checks started to fail. |
| segment group | A segment group is a box of app segments. A rule can name the box instead of each app. |
| self-healing | Self-healing means the app fixes small problems by itself. It tells you what it did, and asks you when it cannot fix one. |
| sensitive data | Sensitive data is private stuff, like card numbers, health notes or secret plans. Only the right people should see it. |
| server group | A server group says which servers run an app and which connector groups can reach them. |
| severity | Severity says how bad a problem is. It goes from info and low up to medium, high and critical. |
| smart isolation | Smart isolation lets Zscaler spot sites that look risky. It opens them in isolation by itself, so they cannot reach your computer. |
| snapshot | A snapshot is a copy of your settings, saved on this computer. You can open it later without the internet. It never holds a secret key. |
| spreadsheet | A spreadsheet is a file with rows and boxes, like a table. Excel can open it. |
| SSL inspection | Most web traffic is locked. SSL inspection lets Zscaler open it and look inside. Without it, Zscaler sees where data goes but not what it is. |
| sub-location | A sub-location is a part of a location, like the guest Wi-Fi of an office. It can have its own settings. |
| success criteria | Success criteria are the things the customer wants to see work. If they all pass, the test was a win. |
| tag | A tag is a short word you stick on a rule or another item, like a label. It helps you find and group things later. |
| tenant | Your tenant is the space your company has in Zscaler. It holds all of your settings. |
| test kit | A test kit is a set of fake files and safe test links. They let you check Zscaler without using real private data. |
| threat category | A threat category is a group of sites Zscaler knows are bad, like phishing or malware. Threat protection blocks them for everyone. |
| tier | A tier is how strict the baseline is. Strict blocks the most, and Permissive blocks the least. |
| time window | A time window is a set of days and hours, like work hours. A rule with one only acts at those times. |
| to-do | A to-do is a small job you write down so you do not forget it. You tick it off when it is done. |
| traffic river | A traffic river is a moving picture of your web traffic. Each stream is as wide as its share, and dots show the traffic going by. |
| trusted network | A trusted network is a network you own, like the office one. It says where a device is, not if the device is safe. |
| Trusted Resolver | The Trusted Resolver is the Zscaler service that looks up web names. It keeps people off bad sites. |
| URL filtering | URL filtering lets people visit some kinds of websites and stops others, like games or gambling. |
| vanity domain | The vanity domain is the short name of your company in Zscaler. In acme.zslogin.net, it is acme. |
| watermark | A watermark is faint text on the screen, like your name and the time. If someone takes a photo of the screen, it shows who saw it. |
| Web probe | A Web probe opens one web page every few minutes. It shows if the page loads and how long it takes. |
| what-if | A what-if asks what would happen for one person. You type a user, a group, a team or a place, and the app checks the rules for them. |
| workload | A workload is a server or cloud machine, not a person. Its traffic leaves through a Cloud or Branch Connector. |
| workload group | A workload group picks workloads by their cloud tags, like all machines tagged Env=prod. Rules can name the group. |
| write mode | Write mode lets this app change your Zscaler. It stays off until you turn it on and type the safety words. |
| Z-Tunnel 2.0 | Z-Tunnel 2.0 is the tunnel Client Connector uses to send all the traffic of a computer to Zscaler, not only web pages. |
| ZDX | ZDX stands for Zscaler Digital Experience. It checks how fast people reach the apps they use. |
| Zero Trust Branch | Zero Trust Branch puts a small Zscaler gateway in each branch office. It sends the office traffic to Zscaler and keeps the devices there apart. |
| Zero Trust Cellular | Zero Trust Cellular sends the traffic of SIM card devices through Zscaler. It warns you when a SIM goes where it should not. |
| Zero Trust Exchange | The Zero Trust Exchange is the Zscaler cloud in the middle. Your traffic goes in, the checks run one by one, and then it goes on or stops. |
| ZIA | ZIA is the part of Zscaler that guards web traffic. Most of the rules this app checks live there. |
| ZIdentity | ZIdentity is the Zscaler site where you manage sign-ins. You make API clients there. |
| ZPA | ZPA is the part of Zscaler that lets people reach the private apps of your company, from home or from the office. |
| Zscaler | Zscaler is a service that sits between your computers and the internet. It checks the traffic to keep your company safe. |
