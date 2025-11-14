from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    gender= models.CharField(max_length=30)
    address= models.CharField(max_length=30)

class detect_botnet_attack(models.Model):

    Fid= models.CharField(max_length=3000)
    SourcedFrom= models.CharField(max_length=3000)
    FileTimeUtc= models.CharField(max_length=3000)
    SourceIp= models.CharField(max_length=3000)
    SourcePort= models.CharField(max_length=3000)
    SourceIpAsnNr= models.CharField(max_length=3000)
    TargetIp= models.CharField(max_length=3000)
    TargetPort= models.CharField(max_length=3000)
    Payload= models.CharField(max_length=3000)
    SourceIpCountryCode= models.CharField(max_length=3000)
    SourceIpRegion= models.CharField(max_length=3000)
    SourceIpCity= models.CharField(max_length=3000)
    SourceIpLatitude= models.CharField(max_length=3000)
    SourceIpLongitude= models.CharField(max_length=3000)
    SourceIpMetroCode= models.CharField(max_length=3000)
    SourceIpAreaCode= models.CharField(max_length=3000)
    HttpRequest= models.CharField(max_length=3000)
    Prediction= models.CharField(max_length=300)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)



