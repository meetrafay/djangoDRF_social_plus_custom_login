import json
import requests
from allauth.socialaccount.models import SocialApp
from auth import settings


def get_google_id_token(validated_data):
    code = validated_data['code']
    print(code)
    url = "https://oauth2.googleapis.com/token"
    google_config_obj = SocialApp.objects.get(provider='google')
    print(google_config_obj)
    payload={
        'code': code,
        'client_id': google_config_obj.client_id,
        'client_secret': google_config_obj.secret,
        'redirect_uri': settings.CALLBACK_URL_YOU_SET_ON_GOOGLE,
        'grant_type': 'authorization_code',
        }
    files=[]
    print(payload)
    payload = json.dumps(payload)
    headers = {}
    response = requests.post(url, data=payload)
    print(response.status_code)
    content = response.json()
    print(content)
    id_token = content.get('id_token')
    return {'access_token': id_token}

def get_google_jwt(access_token):
    try:
        url = "http://127.0.0.1:9000/dj-rest-auth/google/"
        print("url: ",url)
        payload = json.dumps(access_token)
        print(payload)
        headers = {
        'content-type': 'application/json',
        }
        response = requests.request("POST",url, data=access_token)
        if response.status_code==200:
            resp = {"status": True, 'data': response.json()}
        else:
            resp = {"status": False, 'data': "google authentication failed"}
    except Exception as e:
        resp = {"status": False, 'data': "google authentication failed"}
    return resp