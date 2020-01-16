# coding:utf-8
# -----------------------------
# code by cl in 2019-01-02
# use Joern to extract raw explict-check and implicit-check of every callee, which is call instance of
# the argument-sensitive function @function_name interested
# -----------------------------

from database_provider import DBContentsProvider
from ObjDataAndBinFile import ObjDataAndBinFile
from writeXLS import writeXLS

class DisplayEntropyInfo:
    def __init__(self, entropy):
        self.db_provider = DBContentsProvider()
        self.file_io_provider = ObjDataAndBinFile()
        self.entropy = entropy

    def run_gremlin_query(self, query):
        return self.db_provider.run_gremlin_query(query)

    def query_loc_callsite(self, callee_id):
        query = """
            g.v(%s).statements.transform{[g.v(it.functionId).functionToFile.filepath, it.location]}
            """ % callee_id
        result = self.run_gremlin_query(query)
        loc = "%s: %s" % (result[0][0][0], result[0][1])
        return loc

    def display_entropy(self):
        entropys = self.sort_entropy()
        print "\n# Total entropy | implict-check | explict check | callsite id | location\n"
        filename = "Data/entropy_thesis.xls"
        wXLS = writeXLS()
        wXLS.write_excel(filename,entropys)
        for en in entropys:
            print en

    def sort_entropy(self):
        sorted_entropy = []
        for en in self.entropy:
            sum_entropy = sum(en[1:])
            sum_entropy = round(sum_entropy,2)
            loc = self.query_loc_callsite(en[0])
            tmp = []
            tmp.append(sum_entropy)
            tmp.extend(en[1:])
            tmp.append(loc)
            sorted_entropy.append(tmp)
        sorted_entropy = sorted(sorted_entropy, key=lambda entropy: entropy[0], reverse=True)
        return sorted_entropy
