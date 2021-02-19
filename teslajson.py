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
import oauthlib.oauth2


class Connection(object):
    """Connection to Tesla Motors API"""
    def __init__(self,
            email='',
            password='',
            mfa='',
            mfa_id='',
            **kwargs):
        """Initialize connection object
        
        Sets the vehicles field, a list of Vehicle objects
        associated with your account

        Required parameters:
        email: your login for teslamotors.com
        password: your password for teslamotors.com
        
        Optional parameters:
        mfa: multifactor passcode
        mfa_id: multifactor id (if you have multiple MFA devices)
        """
        
        self.email = email
        self.password = password
        self.mfa = mfa
        self.mfa_id = mfa_id
        self.sso_uri = "https://auth.tesla.com"
        self.api_uri = "https://owner-api.teslamotors.com"
        self.data_uri = self.api_uri + "/api/1/"
        self.oauth_uri = self.sso_uri + "/oauth2/v3/"
        self.api_client_id = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
        self.api_client_secret = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"

        self.fetch_token(**kwargs)

        # Get vehicles
        self.vehicles = [Vehicle(v, self) for v in self.request('GET', 'vehicles')]

    def fetch_sso_token(self, **kwargs):
        redirect_uri = self.sso_uri + "/void/callback"

        # Step 1: Obtain the login page
        self.sso_session = requests_oauthlib.OAuth2Session(
          redirect_uri = redirect_uri,
          client_id='ownerapi',
          **kwargs)
        self.__randchars = string.ascii_lowercase+string.digits
        code_verifier = self.__randstr(86)
        hexdigest = hashlib.sha256(code_verifier.encode('utf-8')).hexdigest()
        code_challenge = base64.urlsafe_b64encode(hexdigest.encode('utf-8')).decode('utf-8')
        login_uri = self.oauth_uri+"authorize"
        self.sso_session.params = {
          'client_id': 'ownerapi',
          'code_challenge': code_challenge,
          'code_challenge_method': 'S256',
          'redirect_uri': redirect_uri,
          'response_type': 'code',
          'scope': 'openid email offline_access',
          'state': self.__randstr(24) }
        r = self.sso_session.get(login_uri)
        r.raise_for_status()
        login_data = dict(re.findall(
          '<input type="hidden" name="([^"]*)" value="([^"]*)"', r.text))

        # Step 2: Obtain an authorization code
        login_data['identity'] = self.email
        login_data['credential'] = self.password
        r = self.sso_session.post(login_uri, data=login_data, allow_redirects=False)
        r.raise_for_status()
        
        # Handle MFA
        if (re.search('passcode', r.text)):
          if not self.mfa:
            raise RuntimeError('MFA passcode is required')
          mfa_data = {'transaction_id': login_data['transaction_id']}
          if not self.mfa_id:
            r = self.sso_session.get(self.oauth_uri+"authorize/mfa/factors",
                                     params=mfa_data)
            r.raise_for_status()
            self.mfa_id = r.json()['data'][0]['id']
          mfa_data['passcode'] = self.mfa
          mfa_data['factor_id'] = self.mfa_id
          r = self.sso_session.post(self.oauth_uri+"authorize/mfa/verify",
                                    json=mfa_data)
          r.raise_for_status()
          if not r.json()['data']['valid']:
            raise RuntimeError('Invalid MFA passcode')
          r = self.sso_session.post(login_uri,
                                    data={'transaction_id': login_data['transaction_id']},
                                    allow_redirects=False)
          r.raise_for_status()

        m = re.search('code=([^&]*)',r.headers['location'])
        authorization_code = m.group(1)
        
        # Step 3: Exchange authorization code for bearer token
        self.sso_session.params = None
        self.sso_session.token_url = self.oauth_uri+"token"
        self.sso_session.fetch_token(
            self.sso_session.token_url,
            code=authorization_code, code_verifier=code_verifier,
            include_client_id=True)
      
    def fetch_api_token(self, **kwargs):
        # Step 4: Exchange bearer token for access token
        # (Create the main oauth2 session by calling the super initializer)
        client = oauthlib.oauth2.BackendApplicationClient(
          client_id=self.api_client_id, token_type='Bearer')
        client.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
        self.api_session = requests_oauthlib.OAuth2Session(client=client, **kwargs)
        self.api_session.token_url = self.api_uri+'/oauth/token'
        self.api_session.fetch_token(
          self.api_session.token_url,
          client_secret=self.api_client_secret,
          headers={'Authorization': 'Bearer %s' % self.sso_session.token['access_token']},
          include_client_id=True)
    
    def fetch_token(self, **kwargs):
        # Fetch both tokens
        self.fetch_sso_token(**kwargs)
        self.fetch_api_token(**kwargs)

    def refresh_token(self):
        # Note: We only need to refresh the API token
        self.api_session.refresh_token(self.api_session.token_url)
    
    def __randstr(self, n):
        return ''.join(random.choice(self.__randchars) for i in range(n))
    
    def request(self, method, command, rdata=None):
        try:
          r = self.api_session.request(method, self.data_uri + command, data=rdata)
        except oauthlib.oauth2.TokenExpiredError as e:
          # refresh API token
          self.api_session.refresh_token(self.api_session.token_url)
          return self.requestdata(method, command, rdata)
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
        return self.get('data_request/%s' % name)
    
    def wake_up(self):
        """Wake the vehicle"""
        return self.post('wake_up')
    
    def command(self, name, data={}):
        """Run the command for the vehicle"""
        return self.post('command/%s' % name, data)
    
    def get(self, command):
        """Utility command to get data from API"""
        return self.connection.request('GET', 'vehicles/%i/%s' % (self['id'], command))
    
    def post(self, command, data={}):
        """Utility command to post data to API"""
        return self.connection.request('POST', 'vehicles/%i/%s' % (self['id'], command), data)
