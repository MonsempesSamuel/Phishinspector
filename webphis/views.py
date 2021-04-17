from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.template import Context
import threading, subprocess, multiprocessing, os
# Create your views here.

from .phish_lib import main, phishinspector
from .phish_lib.docker import phish_launcher
from webphis.models import Global_Stats,History_Global_Stats,Downloaded_File
from django.conf import settings
import logging
logger = logging.getLogger('phishinspector.views')


appname = "webphis" #Default appname if I need to changed appname
context = { #Default context
    "app": appname,
}

t_update_dl = None


def test_function(request):
    a = Global_Stats.objects.exclude(phishtank_id__in=list(Downloaded_File.objects.values_list('ref_id', flat=True))).count()

    qs1 = Global_Stats.objects.values_list("phishtank_id")
    qs2 = Downloaded_File.objects.values_list("ref_id")
    response = qs1.difference(qs2).order_by("phishtank_id").count()
    return HttpResponse(str(response) + " / " + str(qs1.count()) + " / " + str(a))

def search_personal_data(request):
    """
    Input: txt file content
    Output: List of password found and line number
    Output1: List of user found and line number
    """
    personal_data_dict = {}
    files = os.listdir(settings.FILESTORE_PATH)
    for file in files:
        if not file.endswith('.txt'):
            pass
        else:
            f = open(settings.FILESTORE_PATH + file,'r')
            content = f.readlines()
            line_number = 0
            for line in content:
                if line.rstrip().endswith(":"):
                    pass
                else:
                    line_number = line_number + 1
                    line_lower = line.lower()
                    if "pass" in line_lower:
                        personal_data_dict[file + ": " + str(line_number)] = line
                    elif "user" in line_lower:
                        personal_data_dict[file + ": " + str(line_number)] = line
                    elif "mail" in line_lower:
                        personal_data_dict[file + ": " + str(line_number)] = line
                    # elif "login" in line_lower:
                    #     personal_data_dict[file + ": " + str(line_number)] = line
    context = {
        "app": appname,
        "personal_data_dict": personal_data_dict,
        "dict_lenght": len(personal_data_dict),
    }
    logger.info('Personal data request completed. {} values found'.format(len(personal_data_dict)))
    return render(request, 'webphis/search_personal_data.html', context)
    # files = os.listdir(settings.FILESTORE_PATH)
    # for file in files:
    #     if not file.endswith('.txt'):
    #         pass
    #     password_dict, user_dict = analyze_text_file(settings.FILESTORE_PATH,file)
    #     return HttpResponse(str(password_dict))

def download_tcpdump_human(request):
    # phish_launcher.convert_tcpdump("/tmp/tcpdump-wireshark-binary","/tmp/tcpdump-wireshark-human")
    output = phish_launcher.print_file("/tmp/tcpdump-wireshark-human")
    return HttpResponse(str(output.output.decode('ascii')), content_type='text/plain')

def run_tcpdump(request):
    # phish_launcher.convert_tcpdump("/tmp/tcpdump-wireshark-binary","/tmp/tcpdump-wireshark-human")
    output = phish_launcher.run_tcpdump()
    return HttpResponse(str('OK'))


def download_tcpdump_wireshark(request):
    output = phish_launcher.print_tcpdump_binary("/tmp/tcpdump-wireshark-binary")
    return HttpResponse(str(output.output), content_type='application/octet-stream')

def download_file(request, phishtank_pk):
    file = Downloaded_File.objects.get(pk=phishtank_pk)
    # source = Global_Stats.objects.get(phishtank_id=file.ref_id)
    filename = file.URL.rsplit('/')[-1] # Same as phishinspector lib. Need it to retrieve filename
    file_path = settings.FILESTORE_PATH + str(file.ref_id) + "-" + filename
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(filename)
            return response
    raise HttpResponseNotFound("Page not found")


def index(request):
    return render(request, 'webphis/home.html', context)

def update_global_stats(request):
    responses = main.update_from_phishtank()
    context = {
        "app": appname,
        "chrono": responses,
        # "new_entries": responses[1],
    }
    return render(request, 'webphis/global_stats_updated.html', context)

def view_global_stats(request):
    query_results = Global_Stats.objects.all()[:200]
    import logging
    logger = logging.getLogger(__name__)
    logger.info('TEST')
    context = {
        "app": appname,
        "query_results": query_results,
        "history": History_Global_Stats.objects.all()
    }
    return render(request, 'webphis/global_stats.html', context)

def view_downloaded_file(request):
    query_results = Downloaded_File.objects.all()
    context = {
        "app": appname,
        "query_results": query_results,
    }
    return render(request, 'webphis/downloaded_file.html', context)

def update_downloaded_file(request):
    global t_update_dl
    if t_update_dl is None:
        t_update_dl = threading.Thread(target=phishinspector.main)
        t_update_dl.start()
    count = phishinspector.get_loop_count()
    progress, done = phishinspector.check_dl()
    context = {
        "app": appname,
        "count": count,
        "progress": progress,
        "done": done,
        "done_lenght": len(done),
    }
    return render(request, 'webphis/downloaded_file_updated.html', context)

def file_details(request, phishtank_pk):
    file = Downloaded_File.objects.get(pk=phishtank_pk)
    source = Global_Stats.objects.get(phishtank_id=file.ref_id)
    same_files = Downloaded_File.objects.filter(sha1_hex=file.sha1_hex)
    same_websites = list()
    for site in same_files:
        same_websites.append(Global_Stats.objects.get(phishtank_id=site.ref_id))
    filename = file.URL.rsplit('/')[-1] # Same as phishinspector lib. Need it to retrieve filename
    path = settings.FILESTORE_PATH + str(source.phishtank_id) + "-" + filename
    context = {
        "app": appname,
        "file": file,
        "email_list": file.email_list.strip('][').split(', ') if file.email_list is not None else None ,
        "source": source,
        "path": path,
        "filename": filename,
        "same_websites": same_websites,
        }
    return render(request, 'webphis/file_details.html', context)

def docker(request, phishtank_pk):
    if phishtank_pk == 0:
        try:
            phish_launcher.stop_container() #If ID is 0 then stop the container. This is not a good practice.
            return HttpResponse("Docker container has been stopped.")
        except:
            return HttpResponse("Docker container SIGTERM(stop) and SIGKILL(force stop) failed")
    import zipfile,time,shutil,tarfile
    # DO with https://docker-py.readthedocs.io/en/stable/
    file = Downloaded_File.objects.get(pk=phishtank_pk)
    # source = Global_Stats.objects.get(phishtank_id=file.ref_id)
    filename = file.URL.rsplit('/')[-1] # Same as phishinspector lib. Need it to retrieve filename
    full_path = settings.FILESTORE_PATH + str(file.ref_id) + "-" + filename
    # full_path = os.path.abspath(path)

    if phish_launcher.check_if_running == 0:
        return HttpResponse("Apache2 server is already running. Please stop the current container before starting a new one.")
    else:
        phish_launcher.initialize(full_path)
        return HttpResponse('Apache2 server is now available at: <a href="http://localhost:8080">http://localhost:8080</a> <br> Apache2 server is now available at: <a href="http://phish-inspector.labs-linux.com:8080">http://phish-inspector.labs-linux.com:8080</a>')

def map(request):
    import json
    query_results = Global_Stats.objects.all()
    data = list()
    for item in query_results:
        if item.lat and item.long is not None:
            entry = {
                'name': item.country_iso,
                'country': item.country,
                'lat': item.lat,
                'lng': item.long,
            }
            data.append(entry)
    out = json.dumps(data)
    context = {
        "app": appname,
        "json_map_data": out,
        # "query_results": query_results,
    }
    logger.info('Map request completed.')
    return render(request, 'webphis/map.html', context) #{"name":"CA","city":"America/Toronto | PhishTank:6806320","lat":43.7807,"lng":-79.2855,}
