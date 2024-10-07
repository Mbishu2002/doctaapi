from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Doctor, NormalUser, Booking, Notification, Rating, Message, Availability, User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                 'profile_photo', 'is_doctor', 'is_normal_user']
        read_only_fields = ['is_doctor', 'is_normal_user']
        extra_kwargs = {
            'password': {'write_only': True}
        }


    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance

class DoctorSerializer(serializers.ModelSerializer):
    user = UserSerializer()
    rating = serializers.SerializerMethodField()
    availability_slots = serializers.SerializerMethodField()

    class Meta:
        model = Doctor
        fields = ['id', 'user', 'specialization', 'institution', 
                 'availability_status', 'rating', 'availability_slots']

    def get_rating(self, obj):
        ratings = obj.ratings.all()
        if not ratings:
            return None
        return sum(r.rating for r in ratings) / len(ratings)

    def get_availability_slots(self, obj):
        return AvailabilitySerializer(obj.availabilities.all(), many=True).data

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        password = user_data.pop('password', None)
        
        # Create user first
        user = User.objects.create(**user_data)
        if password:
            user.set_password(password)
        user.is_doctor = True
        user.save()
        
        # Create doctor profile
        doctor = Doctor.objects.create(user=user, **validated_data)
        return doctor

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        
        # Update user
        user = instance.user
        for attr, value in user_data.items():
            if attr != 'password':
                setattr(user, attr, value)
        if 'password' in user_data:
            user.set_password(user_data['password'])
        user.save()
        
        # Update doctor
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        return instance

class NormalUserSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = NormalUser
        fields = ['id', 'user']

    def create(self, validated_data):
        user_data = validated_data.pop('user')
        password = user_data.pop('password', None)
        
        # Create user first
        user = User.objects.create(**user_data)
        if password:
            user.set_password(password)
        user.is_normal_user = True
        user.save()
        
        # Create normal user profile
        normal_user = NormalUser.objects.create(user=user, **validated_data)
        return normal_user

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        
        # Update user
        user = instance.user
        for attr, value in user_data.items():
            if attr != 'password':
                setattr(user, attr, value)
        if 'password' in user_data:
            user.set_password(user_data['password'])
        user.save()
        
        # Update normal user
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        return instance

class AvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Availability
        fields = ['id', 'doctor', 'day', 'start_time', 'end_time']

    def validate(self, data):
        if data['start_time'] >= data['end_time']:
            raise serializers.ValidationError("End time must be after start time")
        return data

    def create(self, validated_data):
        return Availability.objects.create(**validated_data)

class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['id', 'user', 'doctor', 'availability', 'appointment_time']

    def create(self, validated_data):
        user = validated_data.pop('user', None)
        if not user:
            user = self.context['request'].user.normaluser
        return Booking.objects.create(user=user, **validated_data)

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'recipient', 'message', 'created_at', 'read']
        read_only_fields = ['created_at']

class RatingSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Rating
        fields = ['id', 'user', 'doctor', 'rating', 'review', 'created_at']
        read_only_fields = ['created_at']

    def validate_rating(self, value):
        if not 1 <= value <= 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value

    def validate(self, data):
        request = self.context.get('request')
        if not request or not request.user.is_normal_user:
            raise serializers.ValidationError(
                "Only normal users can create ratings"
            )
        
        # Check if user has already rated this doctor
        user = NormalUser.objects.get(user=request.user)
        if Rating.objects.filter(user=user, doctor=data['doctor']).exists():
            raise serializers.ValidationError(
                "You have already rated this doctor"
            )
        
        return data

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(read_only=True)
    receiver = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    sender_name = serializers.SerializerMethodField(read_only=True)
    receiver_name = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'sender_name', 'receiver_name', 'content', 'timestamp']

    def get_sender_name(self, obj):
        return obj.sender.username if obj.sender else None

    def get_receiver_name(self, obj):
        return obj.receiver.username if obj.receiver else None