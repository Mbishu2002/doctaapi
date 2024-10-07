from django.contrib.auth import authenticate, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import check_password,make_password
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime
from .models import Doctor, NormalUser, Booking, Notification, Rating, Message, Availability, OTP, CustomToken, User
from .serializers import (
    UserSerializer, 
    DoctorSerializer, 
    NormalUserSerializer, 
    BookingSerializer, 
    NotificationSerializer, 
    RatingSerializer, 
    MessageSerializer, 
    AvailabilitySerializer
)
import pyotp
import random
import string
from rest_framework import generics
from django.db.models import Q
from .customtokenauth import CustomTokenAuthentication
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
import logging

logger = logging.getLogger(__name__)


# Helper function to send OTP via email
def send_otp_via_email(user):
    otp_obj, created = OTP.objects.get_or_create(user=user)
    otp = otp_obj.generate_otp()
    subject = 'Your OTP Code'
    message = f'Your OTP code is {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    send_mail(subject, message, email_from, recipient_list)

# Register new normal user
@api_view(['POST'])
@permission_classes([AllowAny])
def register_normal_user(request):
    user_data = request.data
    serializer = NormalUserSerializer(data={'user': user_data})
    if serializer.is_valid():
        normal_user = serializer.save()
        token, created = CustomToken.objects.get_or_create(normal_user=normal_user)
        send_otp_via_email(normal_user.user)
        return Response({
            'token': token.key,
            'user': UserSerializer(normal_user.user).data,
            'role': 'normalUser'
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Register new doctor
@api_view(['POST'])
@permission_classes([AllowAny])
def register_doctor(request):
    user_data = request.data
    logger.info(f"Doctor registration request received with username: {user_data.get('username')}:{user_data.get('password')}")
    email = request.data.get('email', '').strip().lower()
    password = request.data.get('password')
    
    
    serializer = DoctorSerializer(data={'user': user_data})
    if serializer.is_valid():
        doctor = serializer.save()
       # Verify the user was actually saved
        saved_user = User.objects.filter(email__iexact=email).first()
        if saved_user:
            logger.info(f"User verified in database: {saved_user.email}")
            
            # Check if the password is set correctly
            if saved_user.check_password(password):
                logger.info(f"Password check passed for newly created user: {saved_user.email}")
            else:
                logger.error(f"Password check failed for newly created user: {saved_user.email}")

        token, created = CustomToken.objects.get_or_create(doctor=doctor)
        send_otp_via_email(doctor.user)
        return Response({
            'token': token.key,
            'user': UserSerializer(doctor.user).data,
            'role': 'doctor'
        }, status=status.HTTP_201_CREATED)
    
    logger.error(f"Doctor registration failed. Errors: {serializer.errors}")
    return Response({
        'error': 'Registration failed',
        'details': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

# Login user
@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get('email')
    role = request.data.get('role')
    
    user = User.objects.filter(email=email).first()
    
    if user is None:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)    
    send_otp_via_email(user)
    
    return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

# Add a new function to verify OTP and complete login
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_login_otp(request):
    email = request.data.get('email', '').strip().lower()
    otp = request.data.get('otp')
    role = request.data.get('role')
    
    logger.debug(f"Verifying login OTP for email: {email}")
    
    try:
        validate_email(email)
    except ValidationError:
        logger.error(f"Invalid email format: {email}")
        return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email__iexact=email).first()
    logger.debug(f"User found: {user}, OTP: {otp}")
    
    if not user:
        all_users = User.objects.all()
        logger.debug(f"Total users in database: {all_users.count()}")
        logger.debug(f"All user emails: {[u.email for u in all_users]}")
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if hasattr(user, 'otp'):
        if user.otp.verify_otp(otp):
            logger.info(f"OTP verified successfully for {email}")
            # OTP is valid, proceed with login
            if role == 'doctor' and hasattr(user, 'doctor'):
                token, created = CustomToken.objects.get_or_create(doctor=user.doctor)
                serializer = DoctorSerializer(user.doctor)
            elif role == 'normalUser' and hasattr(user, 'normaluser'):
                token, created = CustomToken.objects.get_or_create(normal_user=user.normaluser)
                serializer = NormalUserSerializer(user.normaluser)
            else:
                logger.warning(f"Invalid role for user: {email}")
                return Response({'error': 'Invalid role for this user'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data,
                'role': role,
                'role_specific_data': serializer.data
            }, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid OTP for {email}")
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        logger.warning(f"No OTP attribute for user: {email}")
        return Response({'error': 'OTP not set for this user'}, status=status.HTTP_400_BAD_REQUEST)

# Send OTP
@api_view(['POST'])
@permission_classes([AllowAny])
def send_otp(request):
    email = request.data.get('email', '').strip().lower()
    try:
        validate_email(email)
    except ValidationError:
        logger.error(f"Invalid email format: {email}")
        return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(Q(email__iexact=email)).first()
    logger.debug(f"Searching for user with email: {email}")
    logger.debug(f"User found: {user}")
    
    if not user:
        # If user not found, let's check all users
        all_users = User.objects.all()
        logger.debug(f"Total users in database: {all_users.count()}")
        logger.debug(f"All user emails: {[u.email for u in all_users]}")
    
    if user:
        send_otp_via_email(user)
        logger.info(f"OTP sent successfully to {email}")
        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
    
    logger.warning(f"User not found for email: {email}")
    return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

# Verify OTP
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    email = request.data.get('email', '').strip().lower()
    otp = request.data.get('otp')
    
    logger.debug(f"Verifying OTP for email: {email}")
    
    try:
        validate_email(email)
    except ValidationError:
        logger.error(f"Invalid email format: {email}")
        return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(email__iexact=email).first()
    logger.debug(f"User found: {user}, OTP: {otp}")
    
    if not user:
        all_users = User.objects.all()
        logger.debug(f"Total users in database: {all_users.count()}")
        logger.debug(f"All user emails: {[u.email for u in all_users]}")
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if hasattr(user, 'otp'):
        if user.otp.verify_otp(otp):
            logger.info(f"OTP verified successfully for {email}")
            return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid OTP for {email}")
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        logger.warning(f"No OTP attribute for user: {email}")
        return Response({'error': 'OTP not set for this user'}, status=status.HTTP_400_BAD_REQUEST)

# Update user profile
@api_view(['PUT'])
@authentication_classes([CustomTokenAuthentication])
def update_profile(request):
    user = request.user
    serializer = UserSerializer(user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        if hasattr(user, 'doctor'):
            doctor_serializer = DoctorSerializer(user, data=request.data, partial=True)
            if doctor_serializer.is_valid():
                doctor_serializer.save()
        elif hasattr(user, 'normaluser'):
            normal_user_serializer = NormalUserSerializer(user.normaluser, data=request.data, partial=True)
            if normal_user_serializer.is_valid():
                normal_user_serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Get user profile
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

# Get doctor profile
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_doctor_profile(request, pk):
    doctor = get_object_or_404(Doctor, pk=pk)
    serializer = DoctorSerializer(doctor)
    return Response(serializer.data)

# Get normal user profile
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_normal_user_profile(request, pk):
    normal_user = get_object_or_404(NormalUser, pk=pk)
    serializer = NormalUserSerializer(normal_user)
    return Response(serializer.data)

# Booking list and create
@api_view(['GET', 'POST'])
@authentication_classes([CustomTokenAuthentication])
def booking_list_create(request):
    if request.method == 'GET':
        if hasattr(request.user, 'doctor'):
            bookings = Booking.objects.filter(doctor=request.user.doctor).distinct()
        elif hasattr(request.user, 'normaluser'):
            bookings = Booking.objects.filter(user=request.user.normaluser).distinct()
        else:
            return Response({'error': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)

        if not bookings:
            return Response({'error': 'No bookings found'}, status=status.HTTP_404_NOT_FOUND)

        # Annotate bookings with doctor's name and user's name
        bookings_with_names = bookings.select_related('doctor__user', 'user__user').values(
            'id', 'appointment_time', 'availability', 'doctor__user__username', 'user__user__username'
        )

        return Response(list(bookings_with_names))

    if request.method == 'POST':
        logger.info(f"Creating booking with data: {request.data}")

        # Extract data from request
        doctor_id = request.data.get('doctor')
        availability_id = request.data.get('availability')
        appointment_time = request.data.get('appointment_time')

        # Validate required fields
        if not all([doctor_id, availability_id, appointment_time]):
            return Response({'error': 'Doctor, availability, and appointment time must be provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Get the user (assuming it's a normal user creating the booking)
        user = request.user.normaluser if hasattr(request.user, 'normaluser') else None
        if not user:
            return Response({'error': 'Only normal users can create bookings'}, status=status.HTTP_403_FORBIDDEN)

        # Prepare data for serializer
        booking_data = {
            'doctor': doctor_id,
            'availability': availability_id,
            'appointment_time': appointment_time,
            'user': user.id
        }

        serializer = BookingSerializer(data=booking_data, context={'request': request})
        if serializer.is_valid():
            booking = serializer.save()
            logger.info(f"Booking created successfully: {booking.id}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            logger.error(f"Booking creation failed. Errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Booking detail, update, and delete
@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([CustomTokenAuthentication])
def booking_detail(request, pk):
    booking = get_object_or_404(Booking, pk=pk)
    if request.method == 'GET':
        serializer = BookingSerializer(booking)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = BookingSerializer(booking, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'DELETE':
        booking.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'POST', 'PUT'])
@authentication_classes([CustomTokenAuthentication])
def availability_list_create(request):
    if not hasattr(request.user, 'doctor'):
        return Response({'error': 'Only doctors can manage availabilities'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        doctor_id = request.query_params.get('doctor_id')
        if not doctor_id:
            return Response({'error': 'Doctor ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        availabilities = Availability.objects.filter(doctor_id=doctor_id)
        serializer = AvailabilitySerializer(availabilities, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        if isinstance(request.data, list):
            created_availabilities = []
            for item in request.data:
                processed_item = process_availability_item(item, request.user.doctor.id)
                if processed_item:
                    serializer = AvailabilitySerializer(data=processed_item)
                    if serializer.is_valid():
                        created_availability = serializer.save()
                        created_availabilities.append(created_availability)
                    else:
                        logger.error(f"Validation error for item: {processed_item}")
                        logger.error(f"Serializer errors: {serializer.errors}")
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            return Response(AvailabilitySerializer(created_availabilities, many=True).data, status=status.HTTP_201_CREATED)
        else:
            processed_data = process_availability_item(request.data, request.user.doctor.id)
            if processed_data:
                serializer = AvailabilitySerializer(data=processed_data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    logger.error(f"Validation error for data: {processed_data}")
                    logger.error(f"Serializer errors: {serializer.errors}")
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'Invalid data provided'}, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'PUT':
        # Handle PUT request for updating availabilities
        availability = Availability.objects.filter(doctor=request.user).first()
        if availability:
            # Ensure doctor is included
            request.data['doctor'] = request.user
            
            serializer = AvailabilitySerializer(availability, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({'error': 'No availability found for this doctor'}, status=status.HTTP_404_NOT_FOUND)

def process_availability_item(item, doctor_id):
    day_mapping = {
        'Monday': 'MON', 'Tuesday': 'TUE', 'Wednesday': 'WED',
        'Thursday': 'THU', 'Friday': 'FRI', 'Saturday': 'SAT', 'Sunday': 'SUN'
    }
    
    processed_item = item.copy()
    processed_item['day'] = day_mapping.get(processed_item.get('day'), processed_item.get('day'))
    processed_item['start_time'] = convert_time_format(processed_item.pop('from', None))
    processed_item['end_time'] = convert_time_format(processed_item.pop('to', None))
    processed_item.pop('enabled', None)
    processed_item['doctor'] = doctor_id

    # Check if start_time and end_time are valid
    if not processed_item['start_time'] or not processed_item['end_time']:
        logger.error(f"Invalid time data: start_time={processed_item['start_time']}, end_time={processed_item['end_time']}")
        return None

    # Check if end_time is after start_time
    if processed_item['start_time'] >= processed_item['end_time']:
        logger.error(f"Invalid time range: start_time={processed_item['start_time']}, end_time={processed_item['end_time']}")
        return None

    logger.debug(f"Processed availability data: {processed_item}")
    return processed_item

def convert_time_format(time_str):
    if not time_str:
        return None
    try:
        time_obj = datetime.strptime(time_str, '%I:%M %p')
        return time_obj.strftime('%H:%M')
    except ValueError:
        try:
            # Try parsing as 24-hour format
            time_obj = datetime.strptime(time_str, '%H:%M')
            return time_str
        except ValueError:
            logger.error(f"Invalid time format: {time_str}")
            return None

def convert_time_format(time_str):
    if time_str:
        try:
            # Parse the input time string
            time_obj = datetime.strptime(time_str, '%I:%M %p')
            # Convert to 24-hour format
            return time_obj.strftime('%H:%M')
        except ValueError:
            # If the input is already in the correct format, return it as is
            return time_str
    return None



# Notification list and create
@api_view(['GET', 'POST'])
@authentication_classes([CustomTokenAuthentication])
def notification_list_create(request):
    if request.method == 'GET':
        notifications = Notification.objects.filter(recipient=request.user)
        serializer = NotificationSerializer(notifications, many=True)
        return Response(serializer.data)
    
    if request.method == 'POST':
        serializer = NotificationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(recipient=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Rating list and create
@api_view(['GET', 'POST'])
@authentication_classes([CustomTokenAuthentication])
def rating_list_create(request):
    if request.method == 'GET':
        if hasattr(request.user, 'doctor'):
            ratings = Rating.objects.filter(doctor=request.user)
        elif hasattr(request.user, 'normaluser'):
            ratings = Rating.objects.filter(user=request.user)
        else:
            return Response({'error': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = RatingSerializer(ratings, many=True)
        return Response(serializer.data)
    
    if request.method == 'POST':
        if hasattr(request.user, 'normaluser'):
            serializer = RatingSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save(user=request.user.normaluser)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Only normal users can create ratings'}, status=status.HTTP_403_FORBIDDEN)

# Message list and create
@api_view(['GET', 'POST'])
@authentication_classes([CustomTokenAuthentication])
def message_list_create(request):
    if request.method == 'GET':
        messages = Message.objects.filter(Q(sender=request.user) | Q(receiver=request.user)).order_by('timestamp')
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)
    
    if request.method == 'POST':
        logger.debug(f"Received message data: {request.data}")
        
        receiver_id = request.data.get('receiver')
        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            logger.error(f"Receiver with id {receiver_id} does not exist")
            return Response({'error': f'Receiver with id {receiver_id} does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create a mutable copy of the request data and add the sender
        mutable_data = request.data.copy()
        mutable_data['sender'] = request.user.id
        
        serializer = MessageSerializer(data=mutable_data, context={'request': request})
        logger.debug(f"Serializer: {serializer}")
        
        if serializer.is_valid():
            # Explicitly set the sender before saving
            message = serializer.save(sender=request.user)
            logger.info(f"Message created successfully for sender {request.user.id} and receiver {receiver_id}")
            return Response(MessageSerializer(message).data, status=status.HTTP_201_CREATED)
        else:
            logger.error(f"Serializer errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Get all doctors
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_doctors(request):
    doctors = Doctor.objects.all()
    serializer = DoctorSerializer(doctors, many=True)
    return Response(serializer.data)

# Get doctor details
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_doctor_details(request, pk):
    doctor = get_object_or_404(Doctor, id=pk)
    serializer = DoctorSerializer(doctor)
    return Response(serializer.data)

# Get user bookings
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_user_bookings(request):
    if hasattr(request.user, 'normaluser'):
        bookings = Booking.objects.filter(user=request.user.normaluser)
    elif hasattr(request.user, 'doctor'):
        bookings = Booking.objects.filter(doctor=request.user.doctor)
    else:
        return Response({'error': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)
    serializer = BookingSerializer(bookings, many=True)
    return Response(serializer.data)

# Get doctor ratings
@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_doctor_ratings(request, doctor_id):
    ratings = Rating.objects.filter(doctor_id=doctor_id)
    serializer = RatingSerializer(ratings, many=True)
    return Response(serializer.data)

# Debug user exists
@api_view(['POST'])
@permission_classes([AllowAny])
def debug_user_exists(request):
    email = request.data.get('email', '').strip().lower()
    user = User.objects.filter(email__iexact=email).first()
    all_users = User.objects.all()
    
    logger.debug(f"Searching for user with email: {email}")
    logger.debug(f"User found: {user}")
    logger.debug(f"All users in the database: {all_users.count()}")
    logger.debug(f"All user emails: {[u.email for u in all_users]}")
    
    if user:
        return Response({'message': 'User found', 'user_id': user.id}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@authentication_classes([CustomTokenAuthentication])
def get_doctor_availability(request, doctor_id):
    availabilities = Availability.objects.filter(doctor_id=doctor_id)
    serializer = AvailabilitySerializer(availabilities, many=True)
    return Response(serializer.data)