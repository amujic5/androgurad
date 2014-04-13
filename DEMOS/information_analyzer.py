__author__ = 'Azzi'
"""
This class analyzes android apk and provides information such as
information about files, permissions and different entry points(activities, services...).
"""
from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.analysis import ganalysis

#change this path to apk
APK_FILE = "Path to apk"

# information about files, permissions and different entry points(activities, services...)
#load apk
a = apk.APK( APK_FILE )
a.show()
print a.get_activities()
print a.androidversion
print a.get_max_sdk_version()
print a.get_min_sdk_version()

#length
print len(a.get_file("classes.dex"))