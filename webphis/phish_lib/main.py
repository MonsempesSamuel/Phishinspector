import shutil, gzip, requests, json, dateutil.parser, hashlib, time
from webphis.models import Global_Stats,History_Global_Stats,Downloaded_File
from geolite2 import geolite2 #pip3 install maxminddb-geolite2
import logging
logger = logging.getLogger('phishinspector.main')


def update_from_phishtank():
    start = time.time()
    responses = dl_from_phishtank()
    data = responses[0]
    history = History_Global_Stats(sha1_hex = responses[1], count_rows = responses[2]) # models auto_now = True
    history.save()
    Global_Stats.objects.exclude(phishtank_id__in=list(Downloaded_File.objects.values_list('ref_id', flat=True))).delete()

    sql_update = []
    sql_create = []
    for entry in data:
        # print(Global_Stats_load_in_ram.objects.get(phishtank_id = entry["phish_id"]))
        if len(entry["details"]) != 0:
            ip_address =entry["details"][0]["ip_address"]
            cidr_block=entry["details"][0]["cidr_block"]
            announcing_network=entry["details"][0]["announcing_network"]
            rir=entry["details"][0]["rir"]
            detail_time=convert_date_iso8601(entry["details"][0]["detail_time"])
        else:
            ip_address = None
            cidr_block = None
            announcing_network = None
            rir = None
            detail_time = None

        try:
            request = Global_Stats.objects.get(phishtank_id = entry["phish_id"]) # Improve perf: select values list ouside the loop.
        except:
            request = False
        geoip = ip_to_location(ip_address)
        if geoip:
            city,country_iso,country,lat,long = geoip
            # location = str(lat) + " " + str(long)
        else:
            city = None
            country_iso = None
            country = None
            location = None
        if request is not False:
            sql_update.append(Global_Stats(pk = request.pk,
                phishtank_id=entry["phish_id"],
                URL=entry["url"],
                phish_detail_url=entry["phish_detail_url"],
                submission_time=convert_date_iso8601(entry["submission_time"]),
                verified=convert_to_boolean(entry["verified"]),
                verification_time=convert_date_iso8601(entry["verification_time"]),
                online=convert_to_boolean(entry["online"]),
                target=entry["target"],
                ip_address=ip_address, #IndexError: list index out of range
                cidr_block=cidr_block,
                announcing_network=announcing_network,
                rir=rir,
                detail_time=detail_time,
                city=city,
                country_iso=country_iso,
                country=country,
                lat=lat,
                long=long,
                ))
        else:
            sql_create.append(Global_Stats(phishtank_id=entry["phish_id"],
                URL=entry["url"],
                phish_detail_url=entry["phish_detail_url"],
                submission_time=convert_date_iso8601(entry["submission_time"]),
                verified=convert_to_boolean(entry["verified"]),
                verification_time=convert_date_iso8601(entry["verification_time"]),
                online=convert_to_boolean(entry["online"]),
                target=entry["target"],
                ip_address=ip_address, #IndexError: list index out of range
                cidr_block=cidr_block,
                announcing_network=announcing_network,
                rir=rir,
                detail_time=detail_time,
                city=city,
                country_iso=country_iso,
                country=country,
                lat=lat,
                long=long,
                ))

    Global_Stats.objects.bulk_update(sql_update, ["phishtank_id","URL","phish_detail_url","submission_time","verified","verification_time","online","target","ip_address","cidr_block","announcing_network","rir","detail_time","city","country_iso","country","lat","long"])
    Global_Stats.objects.bulk_create(sql_create)
    # after = Global_Stats.objects.all().count()
    end = time.time()
    # new_entries = after - before
    chrono = end - start
    logger.info('Update from phishtank successfully completed in {} seconds'.format(chrono))
    return(chrono)


def dl_from_phishtank():
    gz_file = requests.get("http://data.phishtank.com/data/online-valid.json.gz")
    sha1 = hashlib.sha1(gz_file.content)
    sha1_hex = sha1.hexdigest()
    content = gzip.decompress(gz_file.content)
    data = json.loads(content.decode('utf-8'))
    count_entries = len(data);
    logger.info('PhishTank file download. {} entries'.format(count_entries))
    return(data, sha1_hex, count_entries)



def read_local_phishtank():
    file = open('online-valid.json')
    data = json.load(file)
    return(data)

def convert_date_iso8601(date_input):
    return(dateutil.parser.parse(date_input))

def convert_to_boolean(string):
    if string == "yes":
        return True
    elif string == "no":
        return False

def ip_to_location(ip):
    if ip:
        reader = geolite2.reader()
        match = reader.get(ip)
        if(match is not None):
          if('location' in match):
              if ('city' in match):
                  city = match['city']['names']['en']
              else:
                  city = ""
              if ('country' in match):
                  country = match['country']['names']['en']
                  country_iso = match['country']['iso_code']
              else:
                  country = ""
                  country_iso = ""
              logger.info('IP to loctaion completed: {} => {}'.format(ip,country))
              return(city,country_iso,country,match['location']['latitude'],match['location']['longitude'])
    else:
        return None
