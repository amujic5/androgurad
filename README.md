##########################################################################
########################### Androguard analyze ###########################
##########################################################################
##########################################################################

1 -] About

Androguard (Android Guard) is primarily a tool written in full python to 
play with :
    - DEX, ODEX
    - APK
    - Android's binary xml
It will be used to analyze crypto libraries usage in Android apps.

2 -] Usage

Androguard library is already in this project in folder androguard,
it has been downloaded from: https://androguard.googlecode.com/hg/.

To use this project copy androguard folder in your library folder or
in your project.

3 -] Android apps

There are some Android apps in ANDRO_APK folder that can be analyzed.
They have been obtained using "apk downloader" Android app downloaded 
from GooglePlay(link: https://play.google.com/store/apps/details?id=apk.downloader). 
It is the only legal way to get it at the moment.

4 -] DEMOS
In folder DEMOS there are several script that analyze apk.

5 -] OUTPUT
In OUTPUT folder there are results of analysis of Android apps such as 
control flow graph, xref (shows where is a specific method called), 
dref (where a specific field is used), usage of specific package 
(for example:crypto usage), usage of specific method, source code, etc.
