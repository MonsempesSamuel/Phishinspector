from django.db import models

# Create your models here.
class Global_Stats(models.Model):
    """
        Data are imported from phishtank.org website and stored on the database.
        The application will generate new data about each entry. So additional fields are created:
        - confirmed_target => Which site has been attacked ?
        - tool_used => How is build this phishing site ? Usually Wordpress or simple PHP/HTML.
        - is_referenced_google =>  Can you find this site with google ?
        - imported_since => When this entry has been added to this database

        Time needs to be converted into DateField.
        'yes' and 'no' need to be converted into BooleanField.
    """
    # PhishTank basic info => http://phishtank.org/developer_info.php
    phishtank_id = models.IntegerField()
    URL = models.CharField(max_length=1000)
    phish_detail_url = models.CharField(max_length=1000)
    submission_time = models.DateField()
    verified = models.BooleanField()
    verification_time = models.DateField()
    online = models.BooleanField()
    target = models.CharField(max_length=50)
    # ip_address = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField(protocol='both', unpack_ipv4=False,null=True)
    cidr_block = models.CharField(max_length=50,null=True)
    announcing_network = models.CharField(max_length=50,null=True)
    rir = models.CharField(max_length=50,null=True)
    detail_time = models.DateField(null=True)

    # Added informations
    city = models.CharField(max_length=50,null=True)
    country_iso = models.CharField(max_length=5,null=True)
    country = models.CharField(max_length=50,null=True)
    lat = models.CharField(max_length=50,null=True)
    long = models.CharField(max_length=50,null=True)
    is_referenced_google = models.BooleanField(default=False,blank=True)
    # Move to Downloaded_File ?
    confirmed_target = models.CharField(max_length=50,blank=True)
    tool_used = models.CharField(max_length=50,blank=True)
    imported_since = models.DateField(null=True,blank=True)
    files_found = models.BooleanField(default=False)


class History_Global_Stats(models.Model):
    """
        Write stats after downloading gz file from PhishTank.
        - sha1 hash to know when the source has been updated
        - count entries to display a graph of current online phishing websites
    """
    date = models.DateTimeField(auto_now=True)
    sha1_hex = models.CharField(max_length=40)
    count_rows = models.IntegerField()

class Downloaded_File(models.Model):
    """
        When a file is downloaded from phishing sites => add an entry here.
    """
    ref_id = models.IntegerField()
    URL = models.CharField(max_length=1000)
    sha1_hex = models.CharField(max_length=40)
    extension = models.CharField(max_length=10)
    first_dl_date = models.DateTimeField()
    last_dl_date = models.DateTimeField()
    sha1_is_same_count = models.IntegerField(default=0)
    sha1_is_not_same_count = models.IntegerField(default=0)

    # Added informations => Password ? Kits ? Apache2 site open ?
    email_list = models.CharField(max_length=3000,null=True)
    h_inspection_date = models.DateTimeField(null=True,blank=True)
    score = models.IntegerField(null=True)
    type = models.CharField(max_length=50,blank=True)
    # tool_used = models.CharField(max_length=50,blank=True)
    comment = models.CharField(max_length=2000,blank=True)

class Emails_Found(models.Model):
    """
    """
    ref_id = models.IntegerField()
    email = models.CharField(max_length=100)

# class Personal_Data(models.Model):
#     """
#     """
#     ref_id = models.IntegerField()
#     firstname = models.CharField(max_length=100)
#     lastname = models.CharField(max_length=100)
#     email = models.CharField(max_length=100)
#     login = models.CharField(max_length=100)
#     password = models.CharField(max_length=100)
#     credit_card = models.CharField(max_length=100)
