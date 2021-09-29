# GVE_DevNet_Techcombank_UmbrellaAlerts
WebEx/Email/SMS alerts for Umbrella Blocked requests based on Umbrella blocked requests

## Contacts
* Ozair Saiyad
* Josh Ingeniero


## Solution Components
* Python Umbrella API's Meraki Dashboard API's

#### Set up a Python venv
First make sure that you have Python 3 installed on your machine. We will then be using venv to create
an isolated environment with only the necessary packages.

##### Install virtualenv via pip
```
$ pip install virtualenv
```
##### Create a new venv
```
Change to your project folder
$ cd GVE_Devnet_Techcombank_UmbrellaAlerts
Create the venv
$ virtualenv venv
Activate your venv
$ source venv/bin/activate
```
#### Install dependencies
In the alerter folder: 
```
$ pip install -r requirements.txt
```

#### API Secrets
Create a [env_vars.py](env_vars.py) file where you will fill in your API Keys/Secrets and other sensitive variables

## Setup:

### Webex Bot

#### Bot Creation
You must create a Webex Bot using the Developer pages [here](https://developer.webex.com/docs/bots).
You would then obtain the Bot ID, Token, and Email which will be used for this application.
Currently the code calls the Rainshield bot for notifications

```python
# Webex Bot
BOT_ID = 'BOT_ID'
BOT_TOKEN = 'BOT_TOKEN'
BOT_EMAIL = 'yoursasebot@webex.bot'
```
You would also need to fill in the room details for where you want to be notified in the [env_vars.py](env_vars.py) file :

```
DNS_ROOMID='DNS_ROOMID'
DLP_ROOMID='DLP_ROOMID'
PROXY_ROOMID='PROXY_ROOMID'
```

### Umbrella details:
You would need to have access to an Umbrella deployment with data on Top Destinations.

To generate a Reporting Key and Secret, refer to the documentation [here](https://developer.cisco.com/docs/cloud-security/#!reporting-v2-getting-started).
You will use this for getting data on Top Destinations for this application.

You must obtain your Organization ID. You may do so by copying the numbers found in your Umbrella dashboard's
URL like this example:
```
https://dashboard.umbrella.com/o/*******/#/overview
```
Where the ******* stands for the Organization ID.

Fill in the details of your Umbrella deployment in [env_vars.py](env_vars.py) file.
```python
# Umbrella
UMBRELLA_REPORTING_KEY = 'REPORTING_KEY'
UMBRELLA_REPORTING_SECRET = 'REPORTING_SECRET'
UMBRELLA_ORG_ID = 'ORG_ID'


```
## Twilio setup for SMS
If you would like to use text method alerts, there is a function inside alerter.py named 'send_text_alert' based on the Twilio API which you can use. To get the parameters to have a successful API call and send the text:
* you need to make an account [here](https://www.twilio.com) 
* go to the  messaging section on the right-side toolbar
* click on overview, and copy your #API credentials
* From the messaging toolbar again, click on try it out, followed by'Send an SMS' 
* This will bring you to a page where you can enter the target phone number, and automatically see a code snippet with which you can you can fill in the relevant fields in alerter.py
  

## Usage

Once you activate your virtual environment, which will contain resources needed for operation, you may simply run the following in the terminal at the **alerter folder:


    $ python3 alerter.py



# Screenshots

![BotWorking](/IMAGES/BotWorking.png)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
