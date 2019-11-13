# meraki-talos-site-check

> This will check your Meraki Client destination sites against the TalosIntelligence Blacklist and generate a report. The report will have sites ACTIVE blacklist sites that have been visited on your network and also it will have site that were once blacklisted but are currently INACTIVE.  This application might evolve, but will for right now, when you run the application it creates an Excel spreadsheet report of its findings.

## Prereqs

1. Python and pip package manager installed on your host computer / dev machine.

2. Active Meraki Account
3. Meraki API key
4. Git installed on computer

## Running it

Using git on command line...

`git clone https://github.com/JockDaRock/meraki-talos-site-check`

and then

`cd meraki-talos-site-check`

In a text editor edit lines 155 and 156 of `meraki_site_check.py` with your Meraki Network ID and Meraki API Key.

Then run the following commands

`pip3 install -r requirements.txt`

and then

`python3 meraki_site_check.py`

