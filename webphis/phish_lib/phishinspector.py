import psutil, os, requests, hashlib, datetime, multiprocessing, time, threading, shutil,zipfile
from urllib.parse import urlparse, urljoin, unquote
from webphis.models import Global_Stats, Downloaded_File
from django.utils import timezone
from bs4 import BeautifulSoup
from django.conf import settings
import logging
logger = logging.getLogger('phishinspector.phishinspector')


class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'

loop_count = 0
total_rows = 0
is_scanning = False
manager = multiprocessing.Manager() # https://blog.ruanbekker.com/blog/2019/02/19/sharing-global-variables-in-python-using-multiprocessing/
dl_progress = manager.dict()
dl_done = manager.dict()

def search_files(url):
    # print("The URL is : ",url)
    parts = urlparse(url)
    if url[-1] == "/" and len(parts.path) > 1:
        url = url[:-1]
        # print(url)
    path_end = parts.path[-1]
    path_len = len(parts.path)
    paths = parts.path.split('/')[1:]
    if path_end == "/" and path_len == 1: # if http://url.com/ => exit function, can't try anything
        return
    l = list()
    for i in range(0, len(paths)):
        if paths[i] == "":
            return
        phish_url = '{}://{}/{}'.format(parts.scheme, parts.netloc,'/'.join(paths[:len(paths) - i]))
        var = guess_file(phish_url,"zip")
        if var is not None:
            l.append(var)
        var = guess_file(phish_url,"tar.gz")
        if var is not None:
            l.append(var)
        var = guess_file(phish_url,"tar.xz")
        if var is not None:
            l.append(var)
        var = guess_file(phish_url,"gz")
        if var is not None:
            l.append(var)
        var = guess_file(phish_url,"txt")
        if var is not None:
            l.append(var)
        var = guess_dir(phish_url) #This method may return multiples files as a list => use extend instead of append
        if var is not None:
            l.extend(var)
    return l

# Return the count the number of child process
def child_process_count(): #Then use if > 20 then .wait() process to
    current_process = psutil.Process()
    children = current_process.children(recursive=True)
    return len(children)



def mkdir_p(path):
  try:
      os.makedirs(path)
  except OSError as exc: # Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
          pass
      else: raise

def scan_entry(entry):
    scan = search_files(entry.URL)
    if scan:
        for scan_result in scan:
            download_file(scan_result, settings.FILESTORE_PATH, entry)

# Append the String phish_url and the String file_format and guess if the file exist, return it if yes and return NULL if not
def guess_file(phish_url,file_format):
    guess_url = phish_url + "." + file_format
    try:
      g = requests.head(guess_url, allow_redirects=False, timeout=2, stream=True)
      if not 'content-type' in g.headers:
        return
      # if the content-type isn't a file format, ignore
      if not file_format in g.headers.get('content-type'):
        return
      # hopefully we're working with a file format now...
      logger.info(bcolors.OKGREEN + "[!]  Successful guess! Potential kit found at {}".format(guess_url) + bcolors.ENDC)
      # download_file(guess_url)
      return guess_url
    except requests.exceptions.RequestException:
      # print("[!]  An error occurred connecting to {}".format(guess_url))
      return

def guess_dir(phish_url):
    l = list()
    guess_url = phish_url + "/"
    try:
        r = requests.get(guess_url, allow_redirects=False, timeout=2, stream=True)
    except requests.exceptions.RequestException:
        return

    if "Index of" in r.text:
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a'):
            # skip parent directory link
            if 'Parent Directory' in a.text:
                continue

            # skip invalid hrefs
            href = a['href']
            if href and href[0] == '?':
                continue

            # look for zips, txt and exes
            if href.endswith(".zip"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)
            if href.endswith(".tar.gz"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)
            if href.endswith(".tar.xz"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)
            if href.endswith(".gz"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible phishing kit found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)

            if href.endswith(".txt"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible victim list found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)
            if href.endswith(".csv"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible victim list found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)

            if href.endswith(".exe"):
                guess_url = urljoin(guess_url, href)
                logger.info(bcolors.OKGREEN + "[!]  Possible malware found at {}".format(guess_url) + bcolors.ENDC)
                l.append(guess_url)
    return l


def check_dl():
    global dl_progress
    global dl_done
    return dl_progress, dl_done


def download_file(url,path,entry):
    global dl_progress
    global dl_done

    dl_progress[url] = entry.phishtank_id
    logger.info("Start download for {}, {}".format(entry.phishtank_id, url))
    myfile = requests.get(url)
    logger.info("Download successful for {}, {}".format(entry.phishtank_id, url))
    dl_date = datetime.datetime.now()
    sha1 = hashlib.sha1(myfile.content)
    filename = url.rsplit('/')[-1]
    # Threaded function: check download status
    open(path + str(entry.phishtank_id) + "-" +  filename, 'wb').write(myfile.content)
    # TODO: Create entry table, where is the file, his name, his ID, sha1, extension, first_dl_date if not exist, replace last_dl_date
    dl_date = timezone.now()
    del dl_progress[url]
    dl_done[url] = entry.phishtank_id

    email_list = analyze_archive(path, str(entry.phishtank_id) + "-" +  filename)

    # condition = Downloaded_File.objects.filter(ref_id = entry.phishtank_id).exist()
    # print(condition.ref_id)
    # Downloaded_File.objects.all().delete() # Delete all the table, test/dev only
    try:
        request = Downloaded_File.objects.get(ref_id = entry.phishtank_id, URL = url)
    except:
        request = None

    if request is not None and request.URL == url: # If exist, don't update first_dl_date and phishtank_id
        same, not_same = compare_sha1(sha1.hexdigest(), request)
        sql = Downloaded_File(
            pk = request.pk, # primary key needed to update a SQL row
            URL = url,
            sha1_hex = sha1.hexdigest(),
            extension = os.path.splitext(filename)[1],
            last_dl_date = dl_date,
            sha1_is_same_count = request.sha1_is_same_count + same,
            sha1_is_not_same_count = request.sha1_is_not_same_count + not_same,
            email_list = email_list,
            )
        sql.save(update_fields=["sha1_hex", "extension", "last_dl_date", "sha1_is_same_count", "sha1_is_not_same_count", "email_list"])
        logger.info("Update downloaded file in database: {}, {}, {}".format(entry.phishtank_id, url,dl_date))
    else: # If not exist, create a new row
        sql = Downloaded_File(
            ref_id=entry.phishtank_id,
            URL = url,
            sha1_hex = sha1.hexdigest(),
            extension = os.path.splitext(filename)[1],
            first_dl_date = dl_date,
            last_dl_date = dl_date,
            sha1_is_same_count = 0,
            sha1_is_not_same_count = 0,
            email_list = email_list,
            )
        sql.save()
        logger.info("Create downloaded file in database: {}, {}, {}".format(entry.phishtank_id, url,dl_date))


def analyze_archive(path, input_file):
    """
    Input: ZIP file content
    Output: List of emails used inside the archive
    """
    if not zipfile.is_zipfile(path + input_file):
        return
    analyze_dir = "/tmp/analyze/" + input_file
    input_file = path + input_file
    try:
        shutil.rmtree(analyze_dir)
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
    try:
        os.mkdir(analyze_dir)
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))

    with zipfile.ZipFile(input_file, 'r') as zip_ref:
        zip_ref.extractall(analyze_dir)

    import re,glob
    email_list = list()
    listOfFiles = list()
    for (dirpath, dirnames, filenames) in os.walk(analyze_dir):
        listOfFiles += [os.path.join(dirpath, file) for file in filenames]
    for file in listOfFiles:
        if os.path.isdir(file):
            pass
        else:
            f = open(file,'rb') # re can read and find with binary
            content = f.read()
            lst = re.findall(br'[\w\.-]+@[\w\.-]+(?:\.[\w]+)+', content)
            # lst = re.findall(b'/^w+[+.w-]*@([w-]+.)*w+[w-]*.([a-z]{2,4}|d+)$/i', content)
            f.close()
            email_list.extend(lst)
    final_list = list()
    for element in email_list:
        final_list.append(element.decode('ascii'))
    email_list = final_list
    return email_list


def compare_sha1(new,request):
    if new == request.sha1_hex:
        same = 1
        not_same = 0
    else:
        same = 0
        not_same = 1
    return same, not_same

def check_url(url):
    parts = urlparse(url)
    if (url[-1] == "/" and len(parts.path) == 1) or (len(parts.path) == 0):
        return "without_interest"
    else:
        return "with_interest"

def get_loop_count():
    global loop_count
    global total_rows
    global is_scanning
    return loop_count, total_rows, is_scanning

def main():
    # Downloaded_File.objects.all().delete() # Delete all the table, test/dev only
    global loop_count
    global total_rows
    global is_scanning
    is_scanning = True
    data = Global_Stats.objects.all()
    total_rows = data.count()
    x=0
    for entry in data:

        if check_url(entry.URL) == "without_interest":
            # print("This URL look like http://example.com (",entry["url"],"), there is no possibility for files scan.")
            pass
        else:
            # x = x + 1
            # if x > 1000:
            #     return 0
            # print(entry.__dict__)

            # Test data
            class test_data():
                def __init__(self):
                    import datetime
                    self.id = 6660
                    self.phishtank_id = 6661
                    self.URL = 'http://localhost:8090/file/test.html'
                    # self.URL = 'http://ipv4.download.thinkbroadband.com/512MB/index.html'
                    self.phish_detail_url  = 'http://www.phishtank.com/phish_detail.php?phish_id=6911809'
                    self.submission_time = datetime.date(2021, 1, 5)
                    self.verified = True
                    self.verification_time = datetime.date(2021, 1, 5)
                    self.online = True
                    self.target = 'Caixa'
                    self.ip_address = '35.208.84.187'
                    self.cidr_block = '35.208.0.0/14'
                    self.announcing_network = '19527'
                    self.rir = 'arin'
                    self.detail_time = datetime.date(2021, 1, 5)
                    self.country = ''
                    self.confirmed_target = ''
                    self.tool_used = ''
                    self.is_referenced_google = False
                    self.imported_since = None
                    self.files_found = False
            # entry = test_data()
            # print("ID is", entry.id)
            # End test data
            limit_process = 10
            while child_process_count() > int(limit_process):
                logger.info("Too much concurrent process. Limit is {}. Waiting...".format(limit_process))
                time.sleep(0.1)
                task1.join()

            task1 = multiprocessing.Process(target=scan_entry, args=[entry])
            task1.start()
            logger.info('Scan entry started for {}'.format([entry]))
            loop_count = loop_count + 1

            # scan_entry(entry)
    while child_process_count() != int(0):
        time.sleep(0.1)
    time.sleep(10) # Wait 10s to let web page be updated with count = total and then stop auto refresh. When thread stop => global variables are lost ? I think no => to confirm
    is_scanning = False
    logger.info('Phishinspector successfully completed')
    return 0

        # print(entry.phishtank_id,entry.URL)
