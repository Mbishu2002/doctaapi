from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('register/normal-user/', views.register_normal_user, name='register_normal_user'),
    path('register/doctor/', views.register_doctor, name='register_doctor'),
    path('login/', views.login_user, name='login_user'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),

    # OTP
    path('send_otp/', views.send_otp, name='send_otp'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),

    # Profile
    path('profile/', views.get_user_profile, name='get_user_profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/doctor/', views.get_doctor_profile, name='get_doctor_profile'),
    path('profile/normal-user/', views.get_normal_user_profile, name='get_normal_user_profile'),

    # Bookings
    path('bookings/', views.booking_list_create, name='booking_list_create'),
    path('bookings/', views.booking_detail, name='booking_detail'),

    # Availability
    path('availabilities/', views.availability_list_create, name='availability_list_create'),

    # Notifications
    path('notifications/', views.notification_list_create, name='notification-list'),

    # Ratings
    path('ratings/', views.rating_list_create, name='rating_list_create'),
    path('doctors/<int:doctor_id>/ratings/', views.get_doctor_ratings, name='get_doctor_ratings'),
    # Doctors
    path('doctors/', views.get_doctors, name='get_doctors'),
    path('doctors/<int:pk>/', views.get_doctor_details, name='get_doctor_details'),

    # Message
    path('messages/', views.message_list_create, name='message-list'),

    # Doctor Availability
    path('doctors/<int:doctor_id>/availability/', views.get_doctor_availability, name='get_doctor_availability'),
]
