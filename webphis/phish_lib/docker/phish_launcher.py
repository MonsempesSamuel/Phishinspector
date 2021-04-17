import docker,tarfile,zipfile, os,shutil
import logging
from django.conf import settings
logger = logging.getLogger('phishinspector.phish_launcher')
client = docker.from_env()

def build_image(name):
    try:
        client.images.get(name=name)
        logger.info('Docker {} image already exist'.format(name))
        return(1) # Error because Network already exist
    except:
        client.images.build(path= str(settings.BASE_DIR) + "/webphis/phish_lib/docker/",tag=name, rm=True,forcerm=True)
        logger.info('Docker image creation: Name={}'.format(name))
        return(0) # Network successfully created


def create_network(name,b_internal):
    try:
        client.networks.get(network_id=name,scope="local")
        logger.info('Docker Network already exist')
        return(1) # Error because Network already exist
    except:
        client.networks.create(name, driver="bridge", internal=b_internal, scope="local")
        logger.info('Docker Network creation: Name={} , Internal={}'.format(name,b_internal))
        return(0) # Network successfully created


def run_container(name,net):
    mycontainer = client.containers.run(name,name=name,detach=True,tty=True,ports={'80/tcp': 8080},privileged=True,auto_remove=True)
    # mycontainer.exec_run("echo 'nameserver 1.1.1.1' > /etc/resolv.conf")
    # mycontainer.exec_run("ip route add 1.1.1.1/32 dev eth0") # permit dns resolution
    # mycontainer.exec_run("ip route del default") # block any other type of requests
    mycontainer.exec_run("bash -c '/usr/sbin/tcpdump -l > /tmp/tcpdump-wireshark-human'",privileged=True,detach=True,tty=True)
    logger.info('Container {} started'.format(name))
    return(mycontainer)

def load_apache_files(mycontainer,data):
    mycontainer.exec_run("rm /var/www/html/index.html")
    mycontainer.put_archive("/var/www/html/",data)
    mycontainer.exec_run("sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/tmp/unzip|' /etc/apache2/sites-enabled/000-default.conf")
    mycontainer.exec_run("sed -i 's|#ServerName www.example.com|DirectoryIndex nothing.html.none|' /etc/apache2/sites-enabled/000-default.conf")
    mycontainer.exec_run("service apache2 start")
    logger.info('Webserver ready: container phish-launcher')
    # mycontainer.exec_run("unzip /tmp/source.zip -d /var/www/html/")

def stop_container():
    mycontainer = client.containers.get("phish-launcher")
    mycontainer.stop(timeout=3)
    logger.info('Container {} stopped'.format(name))

def convert_as_tar(kit_file_path):
    tar_file = '/tmp/data.tar.gz'
    unzip_dir = "/tmp/unzip/"
    if os.path.isfile(tar_file):
        os.remove(tar_file)
    try:
        shutil.rmtree(unzip_dir)
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))
    try:
        os.mkdir(unzip_dir)
    except OSError as e:
        print ("Error: %s - %s." % (e.filename, e.strerror))

    with zipfile.ZipFile(kit_file_path, 'r') as zip_ref:
        zip_ref.extractall(unzip_dir)
    with tarfile.open(tar_file, 'w') as archive:
        for file in os.listdir(unzip_dir):
            archive.add(unzip_dir + file)

    with open(tar_file,"rb") as f: tar_data = f.read()
    logger.info('file {} converted as tar for docker use'.format(kit_file_path))
    return tar_data

def check_if_running():
    try:
        client.containers.get("phish-launcher")
        logger.info('Container {} is running. return 0'.format(kit_file_path))
        return 0
    except:
        logger.info('Container {} is not running. return 1'.format(kit_file_path))
        return 1

def convert_tcpdump(tcpdump_in,tcpdump_out):
    mycontainer = client.containers.get("phish-launcher")
    test = mycontainer.exec_run("cp " + tcpdump_in + " " + tcpdump_in + ".copy")
    test = mycontainer.exec_run("bash -c 'tcpdump -r " + tcpdump_in + ".copy" + " > " + tcpdump_out + "'")
    return

def run_tcpdump():
    mycontainer = client.containers.get("phish-launcher")
    test = mycontainer.exec_run("bash -c '/usr/sbin/tcpdump -l > /tmp/tcpdump-wireshark-human'",privileged=True,detach=True,tty=True)
    logger.info('tcpdump started on phish-launcher')
    return



def print_tcpdump_binary(file_path):
    mycontainer = client.containers.get("phish-launcher")
    try:
        output = mycontainer.exec_run("xxd -b " + file_path)
        logger.info('Print tcpdump binary file Successful')
    except:
        output = 'tcpdump file not found'
        logger.info('Can not print tcpdump binary file')
    return output


def print_file(file_path):
    mycontainer = client.containers.get("phish-launcher")
    try:
        output = mycontainer.exec_run("cat " + file_path)
        logger.info('Print file {} Successful'.format(file_path))
    except:
        output = 'tcpdump file not found'
        logger.info('Can not print file {}'.format(file_path))
    return output

def initialize(kit_file_path):
    try:
        client.containers.get("phish-launcher")
        return 1
    except:
        pass
    build_image("phish-launcher")
    create_network("no-internet",False) # no-internet is not an internal network. To block internet we use a wrong gateway
    mycontainer = run_container("phish-launcher","no-internet")
    data = convert_as_tar(kit_file_path)

    load_apache_files(mycontainer,data)
    logger.info('Container phish-launcher completely started')

    return 0
