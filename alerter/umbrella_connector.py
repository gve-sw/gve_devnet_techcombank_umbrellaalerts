#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 Cisco and/or its affiliates.
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

from base64 import b64encode
import requests
import urllib3
import pprint

pp = pprint.PrettyPrinter(indent=4)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Umbrella:
    def __init__(self, reporting_key, reporting_secret, orgId):
        self.reporting_key = reporting_key
        self.reporting_secret = reporting_secret
        self.orgId = orgId
        self.access_token = self.authenticate()
        if not (reporting_key and reporting_secret and orgId):
            raise ValueError("Check empty arguments")
    
    def get_access_token(self):
        return self.access_token

    def authenticate(self):
        # Authentication
        base64string = b64encode(bytes(self.reporting_key + ":" + self.reporting_secret, "utf-8")).decode("ascii")
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {base64string}'
        }
        payload = {}
        params = {}
        endpoint = 'auth/v2/oauth2/token'
        base_url = 'https://management.api.umbrella.com/'
        response = self.call(endpoint, payload, headers, params, method='get', base_url=base_url)
        access_token = response.json()['access_token']
        return access_token

    def call(self, endpoint, payload, headers, params, method, base_url='https://reports.api.umbrella.com/v2/'):
        # Url

        url = base_url + endpoint
        print(url)

        response = requests.request(method, url=url, params=params, headers=headers, data=payload)

        return response
        

    def get_activities(self, initial='-1days', final='now', limit=999):
        params = {}
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        endpoint = f"organizations/{self.orgId}/activity?from={initial}&to={final}&limit={limit}"
        payload = ''
        response = self.call(endpoint, payload, headers, params, "get")
        return response.json()['data']

    def get_blocked_activities(self, initial='-1days', final='now', limit=999):
        params = {}
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        endpoint = f"organizations/{self.orgId}/activity?verdict=blocked&from={initial}&to={final}&limit={limit}"
        payload = ''
        response = self.call(endpoint, payload, headers, params, "get")
        return response.json()['data']


if __name__ == '__main__':
    print('Umbrella Connector Script')
