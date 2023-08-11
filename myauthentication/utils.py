# import os
from django.conf import settings
from django.core.mail import EmailMessage
from rest_framework_simplejwt.tokens import RefreshToken

class Util:
  @staticmethod
  def send_email(data):

    email = EmailMessage(
      subject=data['subject'],
      body=data['body'],
      from_email=settings.DEFAULT_FROM_EMAIL,
      to=[data['to_email']]
      
    )
    email.send()

# class Util:
#   @staticmethod
#   def send_email(data):
#     print("=======")
#     email = EmailMessage(
#       subject=data['subject'],
#       body=data['body'],
#       from_email=os.environ.get('EMAIL_FROM'),
#       to=[data['to_email']]  
#     )
#     email.send()
#     print("++++++++++++++++")
# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
    
    
# import random

# def generate_otp(length=6):
#     """
#     Generate a random OTP (One-Time Password) of the specified length.
#     By default, the length is set to 6 digits.
#     """
#     digits = "0123456789"
#     otp = ""
#     for _ in range(length):
#         otp += random.choice(digits)
#     return otp
