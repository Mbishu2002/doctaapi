from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password
import pyotp
from django.core.exceptions import ValidationError
import binascii
import os
from django.utils.translation import gettext_lazy as _

class User(AbstractUser):
    email = models.EmailField(_('email address'), unique=True)
    is_doctor = models.BooleanField(default=False)
    is_normal_user = models.BooleanField(default=False)
    profile_photo = models.ImageField(upload_to='profile_photos/', blank=True, null=True)
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions_set',
        blank=True,
    )

    def save(self, *args, **kwargs):
        self.email = self.email.lower()
        # Ensure only one role is set
        if self.is_doctor and self.is_normal_user:
            raise ValidationError("User cannot be both doctor and normal user")
        if not self.username:
            self.username = self.email
        
        # Hash the password if it's a new user or the password has changed
        if not self.pk or self._password is not None:
            self.password = make_password(self.password)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

class Doctor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    specialization = models.CharField(max_length=100, blank=True, null=True)
    institution = models.CharField(max_length=200, blank=True, null=True)
    availability_status = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if not self.user.is_doctor:
            self.user.is_doctor = True
            self.user.save()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Dr. {self.user.username} ({self.specialization or 'No specialization'})"

class NormalUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def save(self, *args, **kwargs):
        if not self.user.is_normal_user:
            self.user.is_normal_user = True
            self.user.save()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user.username

class Availability(models.Model):
    DAYS_OF_WEEK = [
        ('MON', 'Monday'),
        ('TUE', 'Tuesday'),
        ('WED', 'Wednesday'),
        ('THU', 'Thursday'),
        ('FRI', 'Friday'),
        ('SAT', 'Saturday'),
        ('SUN', 'Sunday'),
    ]
    
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='availabilities')
    day = models.CharField(max_length=10, choices=DAYS_OF_WEEK)
    start_time = models.TimeField()
    end_time = models.TimeField()

    def clean(self):
        if self.start_time >= self.end_time:
            raise ValidationError("End time must be after start time")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.doctor.user.username} - {self.get_day_display()} from {self.start_time} to {self.end_time}"

class Booking(models.Model):
    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    availability = models.ForeignKey(Availability, on_delete=models.CASCADE)
    appointment_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['appointment_time']),
        ]
        ordering = ['-appointment_time']

    def clean(self):
        if self.appointment_time < timezone.now():
            raise ValidationError("Cannot book appointments in the past")
        
        # Check if the appointment time falls within doctor's availability
        appointment_weekday = self.appointment_time.strftime('%A')[:3].upper()
        if not self.doctor.availabilities.filter(
            day=appointment_weekday,
            start_time__lte=self.appointment_time.time(),
            end_time__gte=self.appointment_time.time()
        ).exists():
            raise ValidationError("Appointment time is outside doctor's availability")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Booking by {self.user.user.username} with Dr. {self.doctor.user.username} on {self.appointment_time}"

class Notification(models.Model):
    recipient = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.recipient.username}"

class Rating(models.Model):
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE, related_name='ratings')
    user = models.ForeignKey(NormalUser, on_delete=models.CASCADE)
    rating = models.IntegerField()
    review = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['doctor', 'user']
        ordering = ['-created_at']

    def clean(self):
        if not (1 <= self.rating <= 5):
            raise ValidationError('Rating must be between 1 and 5')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Rating by {self.user.user.username} for Dr. {self.doctor.user.username}"

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']

    def clean(self):
        if self.sender == self.receiver:
            raise ValidationError("Cannot send message to yourself")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Message from {self.sender.username} to {self.receiver.username}"

class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_secret = models.CharField(max_length=16, default=pyotp.random_base32)
    last_generated = models.DateTimeField(null=True)

    def generate_otp(self):
        totp = pyotp.TOTP(self.otp_secret, interval=300)
        self.last_generated = timezone.now()
        self.save()
        return totp.now()

    def verify_otp(self, otp):
        if not self.last_generated:
            return False
        
        time_elapsed = timezone.now() - self.last_generated
        if time_elapsed.total_seconds() > 300:  # 5 minutes
            return False

        totp = pyotp.TOTP(self.otp_secret, interval=300)
        return totp.verify(otp)

    def __str__(self):
        return f"OTP for {self.user.username}"

class CustomToken(models.Model):
    key = models.CharField(max_length=40, unique=True)
    normal_user = models.ForeignKey(NormalUser, null=True, blank=True, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctor, null=True, blank=True, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def generate_key(self):
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key