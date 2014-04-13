__author__ = 'Azzi'
"""
This class transforms .dex code (Dalvik EXecutable) using decompailer
into u source code.
"""
from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.analysis import ganalysis

#change APK_FILE and PATH_OUTPUT
APK_FILE = "Path to apk"
PATH_OUTPUT = "Path where to output, it should be txt file"

#load apk
a = apk.APK( APK_FILE )
#disassembling the classes.dex file and getting new format(DalvikVMFormat) that is good to work with
d = dvm.DalvikVMFormat( a.get_dex() )

#analyzing classes to get the control flow graph, setup references, and create xref/dref
dx = analysis.VMAnalysis( d )
gx = ganalysis.GVMAnalysis( dx, None )
d.set_vmanalysis( dx )
d.set_gvmanalysis( gx )

#XREF is used to know where is a specific method called
d.create_xref()
#DREF is used to know where a specific field is used
d.create_dref()

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
    print ms.get_source()
    #instead of print u cant write it in file, i recommend it, ms.get_source() returns string
    f.write(ms.get_source())