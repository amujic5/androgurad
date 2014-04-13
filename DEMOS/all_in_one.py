__author__ = 'Azzi'
#!/usr/bin/env python
"""
This class does everything that classes get_source_code, class_analayzer
and information_analyzer do.
"""
from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.analysis import ganalysis

#change APK_FILE and PATH_OUTPUT
APK_FILE = "Path to apk"
PATH_OUTPUT = "Path where to output, it should be txt file"

# information about files, permissions and different entry points(activities, services...)
a = apk.APK( APK_FILE )
a.show()
#print a.get_activities()
#print a.androidversion
#print a.get_max_sdk_version()
#print a.get_min_sdk_version()

#length
#print len(a.get_file("classes.dex"))

#disassembling the classes.dex file and getting new format(DalvikVMFormat) that is good to work with
d = dvm.DalvikVMFormat( a.get_dex() )
# SHOW CLASSes (verbose)
#d.show()

#analyzing classes to get the control flow graph, setup references, and create xref/dref
dx = analysis.VMAnalysis( d )
gx = ganalysis.GVMAnalysis( dx, None )
d.set_vmanalysis( dx )
d.set_gvmanalysis( gx )

#XREF is used to know where is a specific method called
d.create_xref()
#DREF is used to know where a specific field is used
d.create_dref()

#display
d.create_python_export()
#d.pretty_show()

#more info about a method
for x in d.get_methods():
    break
    x.pretty_show()

"""search for a specific method
@param class_name : a regexp for the class name of the method (the package)
@param name : a regexp for the name of the method
@param descriptor : a regexp for the descriptor of the method
@rtype : a list of called methods' paths
"""
#analysis.show_Paths(d, dx.tainted_packages.search_methods(".", "getInstance", "."))

#show usage of specific package (for example:crypto usage)
analysis.show_Paths(d, dx.get_tainted_packages().search_crypto_packages() )
analysis.show_Paths(d, dx.get_tainted_packages().search_packages("Ljava/security/") )
#this method does the same as one above
#for m, _ in dx.get_tainted_packages().search_packages("Ljavax/crypto/") :
#     m.show()
#for m, _ in dx.get_tainted_packages().search_packages("Ljava/security/") :
#     m.show()


f = open(PATH_OUTPUT, 'w')
#way to get source code
vmx = analysis.VMAnalysis(d)
for method in d.get_methods():
    mx = vmx.get_method(method)
    if method.get_code() == None:
      continue
    #print method.get_class_name(), method.get_name(), method.get_descriptor()

    ms = decompile.DvMethod(mx)
    # process to the decompilation
    ms.process()
    # get the source !
    #print ms.get_source()
    #instead of print u cant write it in file, i recommend it, ms.get_source() returns string
    f.write(ms.get_source())


