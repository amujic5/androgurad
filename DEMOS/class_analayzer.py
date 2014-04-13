__author__ = 'Azzi'
"""
This class analyzes apk to get the control flow graph, setup references, and create xref/dref
"""

from androguard.core.bytecodes import dvm, apk
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.analysis import ganalysis

#change this path to apk
APK_FILE = "Path to apk"

#load apk file
a = apk.APK( APK_FILE )

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
#Show (but pretty !) the all information in the object
d.pretty_show()

#show usage of specific package (for example:crypto usage)
analysis.show_Paths(d, dx.get_tainted_packages().search_crypto_packages() )
analysis.show_Paths(d, dx.get_tainted_packages().search_packages("Ljava/security/") )
