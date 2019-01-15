# coding:utf-8
# ---------------------------
# code by Chen Lin 2016-03-26
# uses pickle to save struct data to a file or load stract data from a file
# ---------------------------


import pickle


class ObjDataAndBinFile:

    def objdata2file(self, data, filename):
        output = open(filename, 'wb')
        # Pickle dictionary using protocol 0.
        # pickle.dump(objData, output)

        # Pickle the list using the highest protocol available.
        pickle.dump(data, output, -1)
        output.close()

        # 使用pickle模块从文件中重构python对象
    def binfile2objdata(self, filename):
        pkl_file = open(filename, 'rb')
        data = pickle.load(pkl_file)
        pkl_file.close()
        return data
