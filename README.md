# Django-PhishInspector
PhishInspector as Django App


## Features:
1. Télécharge toutes données sur le site phistank.com
2. Parcours toutes les URLs:
  - Regarde les répertoires et fichiers avec comme extension (.zip, .txt, .tar.gz and .tar.xz).
  - Télécharge les sources disponibles, générer la signature sha1sum et supprimer les doublons téléchargés.
  - Ecris le résultat dans une base de données
3. Affichage sur l'interface graphique :
  - les sources téléchargés, ainsi que les mises à jour.
  - la localisation des serveurs, création d'une carte.
  - le lancement manuel du conteneur docker.
  - les adresses mails se trouvent dans le code source du kit.



## Get Started

Exécutez les instructions suivantes pour créer un environnement de développement.

Initialiser l'environnement virtuel:
```bash
sudo apt install python3.6 python3.6-dev python3.6-venv docker.io
python3.6 -m venv .venv
source .venv/bin/activate
python -m 3.6 install -r requirements.txt
python manage.py makemigrations
python manage.py showmigrations
python manage.py migrate
```

Démarrer Django server:
```bash
python manage.py runserver --settings phishinspector.settings-prod
```
Ensuite, accédez à http://127.0.0.1:8000/.


## Code Structure

```bash
.
├── db.sqlite3
├── manage.py
├── phishinspector
│   ├── asgi.py
│   ├── __init__.py
│   ├── __pycache__
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── README.md
├── requirements.txt
├── templates
│   └── poc_framework
└── webphis
    ├── admin.py
    ├── apps.py
    ├── __init__.py
    ├── migrations
    ├── models.py
    ├── __pycache__
    ├── static
    ├── templates
    ├── tests.py
    ├── urls.py
    └── views.py
```

## CRONJOBS

Certaines fonctions sont appelées automatiquement.
'django_crontab' app, CRONJOBS/settings.py
```bash
python manage.py crontab add/show/remove
crontab -e
```
Ces tâches fonctionnent même lorsque le serveur Web n'est pas en cours d'exécution.
