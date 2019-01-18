# coding:utf-8
# -----------------------------
# coded by Chen Lin in 2019-01-03
# use the information entropy to find defect callees
# -----------------------------

# import sys
import argparse
from find_defect_callees.calculate_pattern_entropy import CalculateEntropy
from find_defect_callees.extract_args_check_patterns import ExtractArgsCheckPatterns
from commonFile.ObjDataAndBinFile import ObjDataAndBinFile
from find_defect_callees.display_data import DisplayEntropyInfo

# sys.path.append("..")


class MiningAbnormalCallee:

    def __init__(self):
        parser = argparse.ArgumentParser(description='Find defect callees.')
        parser.add_argument('--function', '-func',
                            help='the target argument-sensitive function name')
        parser.add_argument("-f", "--filepath",
                            help=' file of check information saved')
        parser.add_argument("-t", "--threshold", required=False, type=int, default=0.5,
                            help="the threshold of the entropy")
        self.args_ = parser.parse_args()

    def run(self):
        if self.args_.function:
            extract_provider = ExtractArgsCheckPatterns(self.args_.function)
            patterns = extract_provider.run_thread()
        if self.args_.filepath:
            patterns = ObjDataAndBinFile.binfile2objdata(self.args_.filepath)
        calculate_provider = CalculateEntropy(patterns, self.args_.threshold)
        entropy = calculate_provider.get_entropy()
        display_provider = DisplayEntropyInfo(entropy)
        display_provider.display_entropy()
        return


if __name__ == '__main__':

    import datetime
    start_time = datetime.datetime.now()
    mining_abnormal_call = MiningAbnormalCallee()
    mining_abnormal_call.run()
    end_time = datetime.datetime.now()
    print "\nTime Used: %s" % (end_time - start_time)


