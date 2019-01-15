# coding:utf-8
# -----------------------------
# coded by Chen Lin in 2019-01-03
# use the information entropy to find defect callees
# -----------------------------

# import sys
import argparse
from find_defect_callees.identify_abnormal_callee import FindAbnorCallee
from find_defect_callees.extract_args_check_patterns import ExtractArgsCheckPatterns

# sys.path.append("..")


class MiningAbnormalCallee:

    def __init__(self):
        parser = argparse.ArgumentParser(description='Find defect callees.')
        parser.add_argument('function', help='the target argument-sensitive function name')
        parser.add_argument('threshold', type=int, help=' the threshold of the entropy')
        self.args_ = parser.parse_args()
        print self.args_
        self.run(self.args_.function, self.args_.threshold)

    def run(self, function_name, threshold):
        get_rawinfo = ExtractArgsCheckPatterns(function_name)

        checkinfo = get_rawinfo.get_checkdata()

        cnv_cstrlib = CnvCstrLib(checkinfo)
        cstrlib = cnv_cstrlib.cnv_checkdata()

        find_abnorcallees = FindAbnorCallee(cstrlib, self.args_.t)
        abnor_callees = find_abnorcallees()

        return abnor_callees


if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    mining_abnormal_call = MiningAbnormalCallee()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


