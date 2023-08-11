from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from auth import settings
from google_auth.utils import get_google_id_token, get_google_jwt
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions,status


class GoogleLogin(SocialLoginView): # if you want to use Authorization Code Grant, use this
    adapter_class = GoogleOAuth2Adapter
    callback_url = settings.CALLBACK_URL_YOU_SET_ON_GOOGLE
    client_class = OAuth2Client


class TrialView(APIView):

    def get(self, request,*args, **kwargs):
        code = self.request.GET.get('code')
        print(code)
        code = {"status":True,'code':code} # get code from google login
        access_token = get_google_id_token(code) # convert google code to ID_token
        print(access_token)
        resp = get_google_jwt(access_token) # checking id_token and register or sign_in user
        print(resp,"ooooo")
        if resp['status'] == False:
            return Response(resp)
        # pk = int(resp['data']['user']['pk'])
        # print(pk)
        # user_obj = User.objects.get(pk= pk)
        # social_account = SocialAccount.objects.get(user = user_obj)
        # try:
        #     profile = Profile.objects.get(user = user_obj)
        #     response = signin_firebase(profile)
        #     firestore_id = get_firestore_id(profile)
        #     resp['data']["firebase_token"] = response
        #     resp['data']["social_account"] = social_account.provider
        #     resp['data']["firestore_id"] = firestore_id
        # except Profile.DoesNotExist:
        #     profile = Profile.objects.create(user = user_obj, role='recruiter')
        #     response = create_firebase_profile(profile)
        #     firestore_id = get_firestore_id(profile)
        #     resp['data']["firebase_token"] = response
        #     resp['data']["social_account"] = social_account.provider
        #     resp['data']["firestore_id"] = firestore_id
        return Response(resp , status= status.HTTP_200_OK)

