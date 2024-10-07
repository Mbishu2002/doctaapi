from django.contrib import admin
from .models import User, Doctor, NormalUser, Availability, Booking, Notification, Rating, Message, OTP, CustomToken

# Register your models here.
admin.site.register(User)
admin.site.register(Doctor)
admin.site.register(NormalUser)
admin.site.register(Availability)
admin.site.register(Booking)
admin.site.register(Notification)
admin.site.register(Rating)
admin.site.register(Message)
admin.site.register(OTP)
admin.site.register(CustomToken)
