#coding:utf-8
#-----------------------------
#2019-01-02
#code by Chenlin
#-----------------------------

import sys
sys.path.append("..")
import commonFile.DataStruct as DataStruct
from extract_args_check_patterns import ExtractArgsCheckPatterns

class CnvCstrLib:
    def __init__(self, checkinfo):
        self.checkinfo = checkinfo
        return

    def cnv_checkdata(self):

        #convert the raw call_checkinfo into an abstract and normalized style,
        # and create @args_cnt constraint sets of each callee
        cstr_lib = ''
        return cstr_lib

if __name__ == '__main__':

    import datetime
    import time
    from commonFile import ObjDataAndBinFile

    starttime = datetime.datetime.now()
    print ("\nBegin time: %s")%starttime

    endtime = datetime.datetime.now()
    print ("\nEnd: %s")%endtime
    print ("\nTime Used: %s")%(endtime - starttime)


