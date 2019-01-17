# coding:utf-8
# -----------------------------
# coded by cl in 2019-01-02
# use the information entropy to measure the difference between the callee's constraint
# and the other callees' constraints, and consider these callees whose measurement are bigger than a threshold value.
# the measure progress will be calculated on every argument, and the sum of all arguments'entropy is the callee's
# entropy. the argument' entropy is the average entropy of each pairs of the target callee with other callees.
# -----------------------------

import math
from commonFile.ObjDataAndBinFile import ObjDataAndBinFile

class FindAbnorCallee:

    def __init__(self, callee_patterns, threshold):
        self.patterns = callee_patterns
        self.args_count = len(callee_patterns[0][1][0])
        self.threshold = threshold

    @staticmethod
    # @p: probability list of each pattern in the pattern-bag
    # @n: counts of object(callee)
    def calculate_entropy(p, n):
        h = 0
        for i in range(0, len(p)):
            h += p[i] * math.log(p[i], 2)
        h = -h/math.log(n, 10)
        return h

    def get_entropy(self):
        entropy = []
        for pattern_path in self.patterns:
            entropy_path = self.entropy_callee(pattern_path)
            entropy.append(entropy_path)

    def entropy_callee(self):
        entropy = []
        bag_implicit = [[] for i in range(self.args_count)]
        bag_explicit = [[] for i in range(self.args_count)]

        # create the bags of patterns
        for pattern_callee in self.patterns:
            callee_implicit_patterns = pattern_callee[1][0]
            for path_implicit_pattern in callee_implicit_patterns:
                for i_arg in range(self.args_count):
                    bag_implicit[i_arg].extend(path_implicit_pattern[i_arg])
            callee_explicit_patterns = pattern_callee[1][1]
            for path_explicit_pattern in callee_explicit_patterns:
                for i_arg in range(self.args_count):
                    bag_explicit[i_arg].extend(path_explicit_pattern[i_arg])
        # remove blank patterns
        bag_implicit.remove([])
        bag_explicit.remove([])
        # calculate the entropy of each path of the @callee_id
        size_bag_implicit = float(len(bag_implicit))
        size_bag_explicit = float(len(bag_explicit))
        size_bag = size_bag_implicit + size_bag_explicit
        for pattern_callee in self.patterns:
            callee_id = pattern_callee[0]
            entropy_implicit_pattern_paths = []
            callee_implicit_patterns = pattern_callee[1][0]
            for path_implicit_pattern in callee_implicit_patterns:
                probability_implicit_pattern_path = []
                for pattern in path_implicit_pattern:
                    probability_implicit_pattern_path.append(bag_implicit.count(pattern)/size_bag_implicit)
                entropy_implicit_pattern_paths.append(
                    self.calculate_entropy(probability_implicit_pattern_path, size_bag_implicit))

            entropy_explicit_pattern_paths = []
            callee_explicit_patterns = pattern_callee[1][1]
            for path_explicit_pattern in callee_explicit_patterns:
                probability_explicit_pattern_path = []
                for pattern in path_explicit_pattern:
                    probability_explicit_pattern_path.append(bag_explicit.count(pattern)/size_bag_explicit)
                entropy_explicit_pattern_paths.append(
                    self.calculate_entropy(probability_explicit_pattern_path, size_bag_explicit))

            entropy.append([callee_id, entropy_implicit_pattern_paths, entropy_explicit_pattern_paths])
            return entropy



    """
    def run(self, function_name):
        cstr_lib = CnvCstrLib().cnv_checkdata(function_name)
        abnor_callees = self.find_abnor_callee(self.cstr_lib)
        return abnor_callees
    """


if __name__ == '__main__':

    import datetime
    starttime = datetime.datetime.now()
    print "\nBegin time: %s"%starttime
    """
    print FindAbnorCallee.calculate_entropy([0.6, 0.4], 4)
    print FindAbnorCallee.calculate_entropy([0.6], 4)
    print FindAbnorCallee.calculate_entropy([0.4], 4)

    print FindAbnorCallee.calculate_entropy([1], 2)
    """

    filename = "../Data/strcpy.data"
    patterns = ObjDataAndBinFile.binfile2objdata(filename)
    identify = FindAbnorCallee(patterns, 1.5)
    identify.entropy_callee()
    endtime = datetime.datetime.now()
    print "\nEnd: %s"%endtime
    print "\nTime Used: %s"%(endtime - starttime)


