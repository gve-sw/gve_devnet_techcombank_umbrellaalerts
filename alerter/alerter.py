#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Josh Ingeniero <jingenie@cisco.com>, Ozair Saiyad <osaiyad@cisco.com>"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import logging
import logging.handlers
import meraki
import pprint
import smtplib
import time
import ssl
import json
import os
import copy
import requests
import datetime

from env_vars import *
from umbrella_connector import *
from tinydb import TinyDB
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client 
from jinja2 import Environment, FileSystemLoader

sched = BlockingScheduler()
# emailSched = BackgroundScheduler()
sending = BackgroundScheduler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
db = TinyDB('db.json')
pp = pprint.PrettyPrinter(indent=2)
env = Environment(
    loader=FileSystemLoader(os.path.join(os.getcwd(), 'templates')))
webex_base_URL = "https://webexapis.com/v1"


def setup_logger(name, log_file, level=logging.DEBUG):
    """To setup as many loggers as you want"""

    # handler = logging.FileHandler(log_file, mode='a')
    handler = logging.handlers.RotatingFileHandler(
        log_file, mode='a', maxBytes=100000000, backupCount=10)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger



def check_blocked_requests():
    requestsLogger = setup_logger('requests_logger', 'requests_logger.log')
    blocked_requests = umbrellaInstance.get_blocked_activities(
        initial='-1days', limit='100')
    return blocked_requests


def store_splash_response(data):
    for item in data:
        db.insert(item)


def prune_data(new_data):
    old_data = db.all()
    
    # list comprehension, generator expression
    pruned_data = [x for x in new_data if x not in old_data]
    print("LENGTH OF OG:", len(pruned_data))
    print("LENGTH OF ND:", len(new_data))

# Use sets to remove duplicates !
    clean_pruned_data = set()
    for data in pruned_data :
        clean_pruned_data.add(json.dumps(data))  #sets can't take dictionary, so we can convert it into JSON strings first

    clean_pruned_data = [json.loads(x) for x in clean_pruned_data]  #make the data structure into a list and convert elements from JSON string to dict


    return list(clean_pruned_data)



# make testing emails


def send_to_email(data):
    if data:
        print('sending')
        message = MIMEMultipart("alternative")
        message["Subject"] = "[ALERT] Blocked Requests"
        message["From"] = sender_email
        message["To"] = receiver_email
        text = """\
    
Hi,
How are you?
Real Python has many great tutorials:
www.realpython.com"""
        print(env)
        template = env.get_template('blocked.html')
        html = template.render(requests=data)
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        message.attach(part1)
        message.attach(part2)

        context = ssl._create_unverified_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", PORT, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email,
                            receiver_email, message.as_string())
        print('data sent!')


def data_classifier(data):
    DNS = [element for element in data if element['type'] == 'dns']
    Proxy = [element for element in data if element['type'] == 'proxy']
    DLP = [element for element in data if 'datalossprevention' in list(
        element.keys()) and element['datalossprevention']['state'] == 'blocked']
    Firewall = [element for element in data if element['type'] == 'firewall']
    classificationLog = setup_logger(
        'Data to be sent to different webex spaces:', 'classifier.log')


    classificationLog.info(f'DNS:/n {DNS}')
    
    print('DLP Length:', len(json.dumps(DLP)))
    print('proxy Length:', len(json.dumps(Proxy)))
    print('dns Length:', len(json.dumps(DNS)))

    
    for incident in DNS:
        create_webex_card(
            incident, 'DNS', DNS_ROOMID)
    for incident in DLP:
        create_webex_card(
            incident, 'DLP', DLP_ROOMID)
            
    for incident in Proxy:
        create_webex_card(
            incident, 'Proxy', PROXY_ROOMID)
            
       
def message_string_creator(raw_json, type):
    if type == 'DNS':
        url = raw_json['domain']
    else:
        url = raw_json['url']

    ipadd = raw_json['externalip']
    date = raw_json['date']
    time = raw_json['time']
    description = raw_json['policycategories']
    description_string = ''.join(str(category) for category in description)
    return 'URL accessed:'+url+'\nip address:'+ipadd+'\ndate of incident:'+date+'\ntime of incidient:'+time+'\ndescription: '+description_string


def message_paginater(message, room):
    bot_access_token = BOT_ACCESS_TOKEN
    length = len(message)
    print(length)

    # paginating if the length is more than the limit of a webex message
    if(length > 7439):
        div = length // 7439
        rem = length % 7439
        print('div', div)
        for i in range(1, div+1):
            sendWebexMessage(message[(i-1)*7439: i*7439],
                             bot_access_token, room)
            print(i*7439)
        if(rem > 0):
            sendWebexMessage(message[-rem:], bot_access_token, room)

    else:
        sendWebexMessage(message, bot_access_token, room)


def main(umbrella_object):
    print('starting')
    logger.info("Starting Umbrella WebEx Alerts")
    current = check_blocked_requests()  # Check the current data for the past interval
    
    current_pruned = prune_data(current)
    

    if current_pruned:  # If pruned data exists, that means there is new data
        # logger.debug(f"Pruned Payload: {current}")
        # print(current_pruned)
        db.truncate()  # Remove old entries
        # print(current_pruned)
        store_splash_response(current_pruned)  # Store new entries
        print("HELLLLOOOO")
        # Add new job to send syslog asynchronously
        sending.add_job(data_classifier, args=[current_pruned])
    else:  # No new data
        logger.debug('Current Payload matches previous or empty')


def create_webex_card(raw_json, type, room):
    bot_access_token = BOT_ACCESS_TOKEN


    ipadd = raw_json['externalip']
    date = raw_json['date']
    time = raw_json['time']
    identity_raw = raw_json['identities']
    identity = ''.join(str(id['label']+', ') for id in identity_raw)
    description = raw_json['policycategories']
    description_string = ''.join(
        str(category['label']) for category in description)
    
    if type == 'DNS':
        url = raw_json['domain']
    else:
        url = raw_json['url']
    if description_string == '':
        description_string = type+' Violation'

    headers = {
        'Authorization': 'Bearer {0}'.format(bot_access_token),
        'Content-type': 'application/json'

    }

    payload = payload = json.dumps({
        "roomId": room,
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "body": [
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {
                                    "type": "Column",
                                    "items": [
                                        {
                                            "type": "Image",
                                            "style": "Person",
                                            "url": "https://www.cisco.com/c/en_au/products/security/what-is-information-security-infosec/jcr:content/Grid/subcategory_atl_8acc/layout-subcategory-atl/anchor_info_127c/image.img.png/1586944373239.png",
                                            "size": "Medium",
                                            "height": "50px"
                                        }
                                    ],
                                    "width": "auto"
                                },
                                {
                                    "type": "Column",
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text": "Cisco",
                                            "weight": "Lighter",
                                            "color": "Accent"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "weight": "Bolder",
                                            "text": "Umbrella Notifier",
                                            "wrap": True,
                                            "color": "Light",
                                            "size": "Large",
                                            "spacing": "Small"
                                        }
                                    ],
                                    "width": "stretch"
                                }
                            ]
                        },
                        {
                            "type": "ColumnSet",
                            "columns": [
                
                                {
                                    "type": "Column",
                                    "width": 65,
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text":"Date: "+ date,
                                            "color": "Light"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "Time: "+time,
                                            "color": "Light",
                                            "weight": "Lighter",
                                            "spacing": "Small"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "Identity: "+identity,
                                            "weight": "Lighter",
                                            "color": "Light",
                                            "spacing": "Small",
                                            "wrap": True
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "Category: "+description_string,
                                            "weight": "Lighter",
                                            "color": "Light",
                                            "spacing": "Small",
                                            "wrap": True

                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "IP Adress: "+ipadd,
                                            "weight": "Lighter",
                                            "color": "Light",
                                            "spacing": "Small",
                                            "wrap": True

                                        }
                                    ]
                                }
                            ],
                            "spacing": "Padding",
                            "horizontalAlignment": "Center"
                        },
                        {
                            "type": "TextBlock",
                            "text": f"Users {identity} tried to access {url} on {date}, {time} which was blocked categorically due to it being a {description_string}",
                            "wrap": True
                        },
                        {
                            "type": "TextBlock",
                            "text": "Check out the incident:"
                        },
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {
                                    "type": "Column",
                                    "width": "auto",
                                    "items": [
                                        {
                                            "type": "Image",
                                            "altText": "",
                                            "url": "https://www.iconsdb.com/icons/preview/black/link-xxl.png",
                                            "size": "Small",
                                            "width": "30px",
                                            "isVisible": True,
                                            "selectAction": {
                                                "type": "Action.OpenUrl",
                                                "url": "https://dashboard.umbrella.com/o/5478593/#/overview"
                                            }
                                        }
                                    ],
                                    "spacing": "Small"
                                },
                                {
                                    "type": "Column",
                                    "width": "auto",
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text": "Umbrella",
                                            "size": "Medium"
                                        }
                                    ],
                                    "verticalContentAlignment": "Center",
                                    "spacing": "Small"
                                }
                            ]
                        }
                    ],
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.2"
                },
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "Submit"
                    }
                ]
            }
        ],
        "markdown": "we"
    })

    print(f'{webex_base_URL}/messages')
    response = requests.request(
        "POST", webex_base_URL+"/messages", data=payload, headers=headers)
    print(response.text)


def sendWebexMessage(message, token, room):

    headers = {
        'Authorization': 'Bearer {0}'.format(token),
        'Content-type': 'application/json',

    }

    payload = json.dumps({
        "roomId": room,
        "text": message
    })

    print(f'{webex_base_URL}/messages')
    response = requests.request(
        "POST", webex_base_URL+"/messages", data=payload, headers=headers)



def send_to_text(message):
    account_sid = 'AC6d71488f0175ff80b7d3b635bb467c42' 
    auth_token = '01d53be4212e8f05f81b1a0fe4fdb798' 
    client = Client(account_sid, auth_token) 
    
    message = client.messages.create(   
                                body=message,
                                messaging_service_sid='MG8fa822e048e3a57b7e12d529df908076',      
                                to='+642102495100' 
                            ) 
    print(message.sid)



#Call this to send a summary email  !
def get_top_categories_summary(umbrellaInstance):
    #parameters
    orgID = 5478593
    access_token = umbrellaInstance.get_access_token()
    headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }
    payload = {}

    #get top 5 categories of the day 
    topCategories = umbrellaInstance.call(endpoint = f'organizations/{orgID}/top-categories?from=-1days&to=now&limit=10&offset=0', headers = headers, payload = payload, params=  {'verdict': 'blocked'}, method = 'GET')
    topCategories_Data = topCategories.json()['data']
    topCategories_IDs = [ element['category']['id'] for element in topCategories_Data if element['rank'] <= 5 ]
    print(topCategories_IDs)

    #get category-summaries of the day 
    categorySummaries = umbrellaInstance.call(endpoint = f'organizations/{orgID}/summaries-by-category?from=-1days&to=now', headers = headers, payload = payload, params=  {}, method = 'GET')
    categorySummaries_Data = categorySummaries.json()['data']
    topCategorySummaries = [ {**element['summary'], **element['category'] }for element in categorySummaries_Data if element['category']['id'] in topCategories_IDs]
    print(json.dumps(topCategorySummaries))

    #send the summary to email
    send_to_email(topCategorySummaries)
    
def send_text_alert(phone_number) : 
    account_sid = '<enter yours here>' 
    auth_token = '[AuthToken]' 
    client = Client(account_sid, auth_token) 
    
    message = client.messages.create(         
                                to='<phonenumber>' 
                            ) 
    
    print(message.sid)



if __name__ == '__main__':

    print('started script')
    logger = setup_logger('backend_logger', 'app.log')

    umbrellaInstance = Umbrella(reporting_key=UMBRELLA_REPORTING_KEY,
                                reporting_secret=UMBRELLA_REPORTING_SECRET, orgId=UMBRELLA_ORG_ID)

    sending.start()

    # call main function every 30s !
    sched.add_job(main, args=[umbrellaInstance],
                  trigger='interval', seconds=30)
    
    sched.add_job(get_top_categories_summary, args = [umbrellaInstance], trigger='interval', minutes = 1440)

    sched.start()
    








