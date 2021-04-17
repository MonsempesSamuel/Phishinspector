from django.urls import path

from . import views # import viwes so we can use them in urls

app_name = 'webphis'
urlpatterns = [
	path('',views.index, name="index"),
	path('map/',views.map, name="map"),
	path('search_personal_data/',views.search_personal_data, name="search_personal_data"),
	path('download_tcpdump_human/',views.download_tcpdump_human, name="download_tcpdump_human"),
	path('download_file/<int:phishtank_pk>',views.download_file, name="download_file"),
	path('global_stats/',views.view_global_stats, name="global_stats"),
	path('file_details/<int:phishtank_pk>',views.file_details, name="file_details"),
	path('docker/<int:phishtank_pk>',views.docker, name="docker"),
	path('downloaded_file/',views.view_downloaded_file, name="downloaded_file"),
	path('update_downloaded_file/',views.update_downloaded_file, name="update_downloaded_file"),
	path('update_global_stats/',views.update_global_stats, name="update_global_stats"),
]
