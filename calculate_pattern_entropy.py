# coding:utf-8
# -----------------------------
# coded by cl in 2019-01-02
# use the information entropy to measure the difference between the callee's constraint
# and the other callees' constraints, and consider these callees whose measurement are bigger than a threshold value.
# the measure progress will be calculated on every argument, and the sum of all arguments'entropy is the callee's
# entropy. the argument' entropy is the average entropy of each pairs of the target callee with other callees.
# -----------------------------

import math
from ObjDataAndBinFile import ObjDataAndBinFile
from display_data import DisplayEntropyInfo

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
    def calculate_entropy(p_list, counts):
        h = 0
        for i in range(0, len(p_list)):
            h += p_list[i] * math.log(p_list[i], 2)
        tmp = math.log(counts, 10)
        if tmp == 0:
            return 0
        else:
            h = -h/math.log(counts, 10)
            return round(h, 2)

    def get_entropy(self):

        entropy = []
        bag_implicit = [[] for i in range(self.args_count)]
        bag_explicit = [[] for i in range(self.args_count)]
        size_bag_implicit = []
        size_bag_explicit = []
        num_paths = 0


        # 1. create the bags of patterns
        for patterns_callee in self.patterns:
            # 计算总路径数
            num_paths = num_paths + len(patterns_callee[1])
            # pattern_path
            callee_id = patterns_callee[0]
            for pattern_path in patterns_callee[1]:
                if pattern_path:
                    if pattern_path == [[], []]:
                        continue
                    path_implicit_patterns = pattern_path[0]
                    path_explicit_patterns = pattern_path[1]
                    # sometimes path_implicit_patterns = [], path_explicit_patterns = []
                    for i_arg in range(self.args_count):
                        if path_implicit_patterns[i_arg]:
                            bag_implicit[i_arg].extend(path_implicit_patterns[i_arg])
                        else:
                            bag_implicit[i_arg].append("NNN")
                    for i_arg in range(self.args_count):
                        if path_explicit_patterns[i_arg]:
                            bag_explicit[i_arg].extend(path_explicit_patterns[i_arg])
                        else:
                            bag_explicit[i_arg].append("NNN")

        for i_arg in range(self.args_count):
            size_bag_implicit.append(float(len(bag_implicit[i_arg])))
            size_bag_explicit.append(float(len(bag_explicit[i_arg])))
            size_bag = size_bag_implicit + size_bag_explicit
        # 2. 判断无需检查情况
        args_implicit_uncheck = []
        args_explicit_uncheck = []
        args_implicit_needcheck = []
        args_explicit_needcheck = []
        for i_arg in range(self.args_count):
            r = bag_implicit[i_arg].count("NNN") / (float(num_paths))
            if r > self.th_uncheck:
                args_implicit_uncheck.append(i_arg)
            if r < self.th_needcheck:
                args_implicit_needcheck.append(i_arg)

            r = bag_explicit[i_arg].count("NNN") / (float(num_paths))
            if r > self.th_uncheck:
                args_explicit_uncheck.append(i_arg)
            if r < self.th_needcheck:
                args_explicit_needcheck.append(i_arg)

        # 3. calculate the entropy of each path of the @callee_id
        for patterns_callee in self.patterns:
            callee_id = patterns_callee[0]
            patterns_paths = patterns_callee[1]
            path_counts = len(patterns_paths)
            for index_path in range(path_counts):
                entropy_explicit = []
                entropy_implicit = []

                #if patterns_paths[index_path] == [[], []]:
                #    entropy.append([callee_id, [], []])
                #    continue
                #if patterns_paths[index_path] == []:
                #    entropy.append([callee_id, [], []])
                #    continue
                path_implicit_patterns = patterns_paths[index_path][0]
                path_explicit_patterns = patterns_paths[index_path][1]

                for i_arg in range(self.args_count):
                    entropy_implicit_tmp = 0
                    entropy_explicit_tmp = 0
                    #判断无检查情况是否大于80%,是则认为该参数无需检查，中断entropy计算
                    # i_arg在无需检查列表中
                    if i_arg in args_implicit_uncheck: # 在无需检查
                        entropy_implicit_tmp = 0
                    elif i_arg in args_implicit_needcheck: # 在必查
                        # 隐式约束的entropy计算
                        implicit_patterns = path_implicit_patterns[i_arg]
                        probability_tmp = []
                        if implicit_patterns:
                            for pattern in implicit_patterns:
                                probability_tmp.append(bag_implicit[i_arg].count(pattern)/size_bag_implicit[i_arg])
                            entropy_implicit_tmp = self.calculate_entropy(probability_tmp, size_bag_implicit[i_arg])
                        else:
                            # 必须检查，而检查为空，entrpy设置为1
                            entropy_implicit_tmp = 1
                    elif (i_arg not in args_implicit_uncheck) and (i_arg not in args_implicit_needcheck): # 普通未知
                        # 隐式约束的entropy计算
                        implicit_patterns = path_implicit_patterns[i_arg]
                        probability_tmp = []
                        if implicit_patterns:
                            for pattern in implicit_patterns:
                                probability_tmp.append(bag_implicit[i_arg].count(pattern)/size_bag_implicit[i_arg])
                            entropy_implicit_tmp = self.calculate_entropy(probability_tmp, size_bag_implicit[i_arg])
                        else:
                            # 需要检查，而检查为空，其约束为NNN，计算entropy
                            probability_tmp.append(bag_implicit[i_arg].count("NNN")/size_bag_implicit[i_arg])
                            entropy_implicit_tmp = self.calculate_entropy(probability_tmp, size_bag_implicit[i_arg])
                    entropy_implicit.append(entropy_implicit_tmp)

                    # undo: 判断无检查情况是否大于80%,是则认为该参数无需检查，中断entropy计算
                    if i_arg in args_explicit_uncheck:# 无需检查
                        entropy_explicit_tmp = 0
                    elif i_arg in args_explicit_needcheck:# 必须检查
                        # 显式约束的entropy计算
                        probability_tmp = []
                        explicit_patterns = path_explicit_patterns[i_arg]
                        if explicit_patterns:
                            for pattern in explicit_patterns:
                                probability_tmp.append(bag_explicit[i_arg].count(pattern)/size_bag_explicit[i_arg])
                            entropy_explicit_tmp = self.calculate_entropy(probability_tmp, size_bag_explicit[i_arg])
                        else: # 必须检查，缺没有检查，entropy为1
                            entropy_explicit_tmp = 1
                    elif (i_arg not in args_explicit_uncheck) and (i_arg not in args_explicit_needcheck): # 普通未知
                    # 显式约束的entropy计算
                        probability_tmp = []
                        explicit_patterns = path_explicit_patterns[i_arg]
                        if explicit_patterns:
                            for pattern in explicit_patterns:
                                probability_tmp.append(bag_explicit[i_arg].count(pattern)/size_bag_explicit[i_arg])
                            entropy_explicit_tmp = self.calculate_entropy(probability_tmp, size_bag_explicit[i_arg])
                        else: # 需要检查，空信息，以NNN作为约束计算entropy
                            probability_tmp.append(bag_explicit[i_arg].count("NNN")/size_bag_explicit[i_arg])
                            entropy_explicit_tmp = self.calculate_entropy(probability_tmp, size_bag_explicit[i_arg])
                    entropy_explicit.append(entropy_explicit_tmp)

                entropy.append([callee_id, entropy_implicit, entropy_explicit])
        return entropy



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


