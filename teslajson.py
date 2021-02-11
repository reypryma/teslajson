""" Simple Python class to access the Tesla JSON API
https://github.com/gglockner/teslajson

The Tesla JSON API is described at:
https://tesla-api.timdorr.com

Example:

import teslajson
c = teslajson.Connection('youremail', 'yourpassword')
v = c.vehicles[0]
v.wake_up()
v.data_request('charge_state')
v.command('charge_start')
"""

import requests_oauthlib
import string
import random
import base64
import hashlib
import re
from oauthlib.oauth2 import BackendApplicationClient


class Connection(requests_oauthlib.OAuth2Session):
    """Connection to Tesla Motors API"""
    def __init__(self,
            email='',
            password=''):
        """Initialize connection object
        
        Sets the vehicles field, a list of Vehicle objects
        associated with your account

        Required parameters:
        email: your login for teslamotors.com
        password: your password for teslamotors.com
        """
        
        self.auth_uri = "https://auth.tesla.com"
        self.base_uri = "https://owner-api.teslamotors.com"
        self.data_uri = self.base_uri + "/api/1/"

        self.get_sso_token(email, password)
        self.fetch_token()

        # Get vehicles
        self.vehicles = [Vehicle(v, self) for v in self.getdata('vehicles')['response']]
            

    def get_sso_token(self, email, password):
        redirect_uri = self.auth_uri + "/void/callback"

        # Step 1: Obtain the login page
        auth_sess = requests_oauthlib.OAuth2Session(
          redirect_uri = redirect_uri,
          client_id='ownerapi')
        self.__randchars = string.ascii_lowercase+string.digits
        code_verifier = self.__randstr(86)
        hexdigest = hashlib.sha256(code_verifier.encode('utf-8')).hexdigest()
        code_challenge = base64.urlsafe_b64encode(hexdigest.encode('utf-8')).decode('utf-8')
        login_uri = self.auth_uri+'/oauth2/v3/authorize'
        auth_sess.params = {
          'client_id': 'ownerapi',
          'code_challenge': code_challenge,
          'code_challenge_method': 'S256',
          'redirect_uri': redirect_uri,
          'response_type': 'code',
          'scope': 'openid email offline_access',
          'state': self.__randstr(24) }
        r = auth_sess.get(login_uri)
        r.raise_for_status()
        login_data = dict(re.findall(
          '<input type="hidden" name="([^"]*)" value="([^"]*)"', r.text))

        # Step 2: Obtain an authorization code
        login_data['identity'] = email
        login_data['credential'] = password
        r = auth_sess.post(login_uri, data=login_data, allow_redirects=False)
        r.raise_for_status()
        m = re.search('code=([^&]*)',r.headers['location'])
        authorization_code = m.group(1)
        
        # Step 3: Exchange authorization code for bearer token
        auth_sess.params = None
        self.sso_token = auth_sess.fetch_token(self.auth_uri+'/oauth2/v3/token',
            code=authorization_code, code_verifier=code_verifier,
            include_client_id=True)
      
    def fetch_token(self,
        client_id = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384",
        client_secret = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"):

        # Step 4: Exchange bearer token for access token
        # (Create the main oauth2 session by calling the super initializer)
        client = BackendApplicationClient(client_id=client_id, token_type='Bearer')
        client.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        super().__init__(client=client)
        super().fetch_token(token_url=self.base_uri+'/oauth/token',
          client_secret=client_secret,
          headers={'Authorization': 'Bearer %s' % self.sso_token['access_token']},
          include_client_id=True)
    
    # TODO: refresh_token
    
    def __randstr(self, n):
        return ''.join(random.choice(self.__randchars) for i in range(n))
    
    def getdata(self, command):
        """Utility command to get data from API"""
        r = self.get(self.data_uri + command)
        r.raise_for_status()
        return r.json()

    def postdata(self, command, data={}):
        """Utility command to post data to API"""
        r = self.post(self.data_uri + command, data)
        r.raise_for_status()
        return r.json()['response']
        

class Vehicle(dict):
    """Vehicle class, subclassed from dictionary.
    
    There are 3 primary methods: wake_up, data_request and command.
    data_request and command both require a name to specify the data
    or command, respectively. These names can be found in the
    Tesla JSON API."""
    def __init__(self, data, connection):
        """Initialize vehicle class
        
        Called automatically by the Connection class
        """
        super(Vehicle, self).__init__(data)
        self.connection = connection
    
    def data_request(self, name):
        """Get vehicle data"""
        result = self.get('data_request/%s' % name)
        return result['response']
    
    def wake_up(self):
        """Wake the vehicle"""
        return self.post('wake_up')
    
    def command(self, name, data={}):
        """Run the command for the vehicle"""
        return self.post('command/%s' % name, data)
    
    def get(self, command):
        """Utility command to get data from API"""
        return self.connection.getdata('vehicles/%i/%s' % (self['id'], command))
    
    def post(self, command, data={}):
        """Utility command to post data to API"""
        return self.connection.postdata('vehicles/%i/%s' % (self['id'], command), data)
