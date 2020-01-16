# coding:utf-8
# -----------------------------
# coded by cl in 2020-01-16 20:44:14
# use the information entropy to measure the difference between the callee's constraint
# and the other callees' constraints, and consider these callees whose measurement are bigger than a threshold value.
# the measure progress will be calculated on every argument, and the sum of all arguments'entropy is the callee's
# entropy. the argument' entropy is the average entropy of each pairs of the target callee with other callees.
# 使用行为（显示，隐式）算一个entropy,默认所有传入的pattern中各个参数都要检查，因此不需要检查的参数不要出现在pattern中
# -----------------------------

import math
from ObjDataAndBinFile import ObjDataAndBinFile
from display_data_thesis import DisplayEntropyInfo

class CalculateEntropy:

    def __init__(self, callee_patterns, threshold):
        self.patterns = callee_patterns
        self.args_count = len(callee_patterns[0][1][0][0])
        self.threshold = threshold
        self.th_uncheck = 0.8 # 空约束比例大于该阈值，则不需约束
        self.th_needcheck = 0.4 # 空约束比例小于该阈值,则需约束
        print "阈值：th_uncheck > %s  th_needcheck < %s" %(self.th_uncheck, self.th_needcheck)
    @staticmethod
    # @p_list: probability list of each pattern in the pattern-bag
    # @counts: counts of object(callee)
    def calculate_entropy(p, counts):
        h = 0
        h += p * math.log(p, 2)
        h = -h/math.log(counts, 10)
        return round(h, 2)

    def get_entropy(self):

        entropy = []
        bag_implicit = [[] for i in range(self.args_count)]
        bag_explicit = [[] for i in range(self.args_count)]
        size_bag_implicit = []
        size_bag_explicit = []
        num_paths = 0

        bag = [[] for i in range(self.args_count)]
        size_bag = []
        tmp_pattern = []
        # 1. create the bags of patterns
        for patterns_callee in self.patterns:
            # 计算总路径数
            num_paths = num_paths + len(patterns_callee[1])
            # pattern_path
            callee_id = patterns_callee[0]
            for pattern_path in patterns_callee[1]:
                tmp_pattern = []
                if pattern_path:
                    if pattern_path == [[], []]:
                        continue
                    path_implicit_patterns = pattern_path[0]
                    path_explicit_patterns = pattern_path[1]
                    # sometimes path_implicit_patterns = [], path_explicit_patterns = []
                    for i_arg in range(self.args_count):
                        tmp_pattern = []
                        tmp_pattern.extend(path_implicit_patterns[i_arg])
                        tmp_pattern.extend(path_explicit_patterns[i_arg])
                        tmp_pattern.sort()
                        bag[i_arg].append(tmp_pattern)

        for i_arg in range(self.args_count):
            size_bag.append(float(len(bag[i_arg])))

        # 2. calculate the entropy of each path of the @callee_id
        for patterns_callee in self.patterns:
            callee_id = patterns_callee[0]
            patterns_paths = patterns_callee[1]
            path_counts = len(patterns_paths)
            for index_path in range(path_counts):
                #if patterns_paths[index_path] == [[], []]:
                #    entropy.append([callee_id, [], []])
                #    continue
                #if patterns_paths[index_path] == []:
                #    entropy.append([callee_id, [], []])
                #    continue
                path_implicit_patterns = patterns_paths[index_path][0]
                path_explicit_patterns = patterns_paths[index_path][1]
                entropy_tmp = []
                for i_arg in range(self.args_count):
                    entropy_arg = 0
                    # entropy计算
                    pattern = path_implicit_patterns[i_arg]
                    pattern.extend(path_explicit_patterns[i_arg])
                    pattern.sort()

                    probability_tmp = self.get_probability(pattern, bag[i_arg])
                    if pattern == []:
                        entropy_arg = 1
                    else:
                        entropy_arg = self.calculate_entropy(probability_tmp, size_bag[i_arg])
                    entropy_tmp.append(entropy_arg)
                tmp = []
                tmp.append(callee_id)
                tmp.extend(entropy_tmp)
                entropy.append(tmp)
        return entropy

    def get_probability(self, pattern, bag):
        num = 0
        for item in bag:
            if pattern == item:
                num = num + 1
        p = round(float(num)/len(bag), 3)
        return p

    """
    def run(self, function_name):
        cstr_lib = CnvCstrLib().cnv_checkdata(function_name)
        abnor_callees = self.find_abnor_callee(self.cstr_lib)
        return abnor_callees
    """
    # Todo: query_pased_control is often failed.


if __name__ == '__main__':

    import datetime

    starttime = datetime.datetime.now()
    print "\nBegin time: %s"%starttime
    """
    print CalculateEntropy.calculate_entropy([0.6, 0.4], 4)
    print CalculateEntropy.calculate_entropy([0.6], 4)
    print CalculateEntropy.calculate_entropy([0.4], 4)

    print CalculateEntropy.calculate_entropy([1], 2)
    """

    filename = "Data/memcpy.data"
    #filename = "Data/42153.data"
    patterns = ObjDataAndBinFile.binfile2objdata(filename)
    identify = CalculateEntropy(patterns, 1.5)
    entropy = identify.get_entropy()

    d = DisplayEntropyInfo(entropy)
    d.display_entropy()
    #print entropy
    endtime = datetime.datetime.now()
    print "\nEnd: %s"%endtime
    print "\nTime Used: %s"%(endtime - starttime)


