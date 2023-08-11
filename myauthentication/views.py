from rest_framework.response import Response
from rest_framework import generics,status
from rest_framework.permissions import AllowAny
from myauthentication.utils import get_tokens_for_user
from .serializers import  SendPasswordResetEmailSerializer, UserChangePasswordSerializer,UserRegistrationSerializer,UserLoginSerializer,UserPasswordResetSerializer
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken


class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer
    

class UserLoginView(APIView):
    
    def post(self, request):

        serializer = UserLoginSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)        
        email = serializer.data.get('email')
        password = serializer.data.get('password')  
        user = authenticate(request=request, username=email, password=password)

        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token':token,'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Email or Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)


        

class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self ,request):
        serializer = UserChangePasswordSerializer(data = request.data,context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
    

class SendPasswordResetEmailView(APIView):
    
    def post (self,request):

        serializer = SendPasswordResetEmailSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        return Response ({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)
        # return Response({'msg': 'Password Reset OTP sent. Please check your email.'}, status=status.HTTP_200_OK)
    

class UserPasswordResetView(APIView):

  def post(self, request,uid,token):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    # serializer = UserPasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
  

class UserLogoutView(APIView):
    
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
         
            return Response({'msg':'Logout Successfully'},status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(str(e),status=status.HTTP_400_BAD_REQUEST)


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        
        data = "Welcome to the Dashboard"
        
        return Response({'data':data},status=status.HTTP_200_OK)







