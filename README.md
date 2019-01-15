### 项目说明
1. 名称：xcallee
2. 目的：通过比较参数敏感型函数的不同调用实例的参数约束，采用信息熵度量其差异性，将异常的调用实例推断为存在缺陷的调用实例
3. 实现平台：基于joern平台
4. 时间：2019年01月
5. 作者：cl

### 文件说明
1. statsDataGen:定义代码库统计数据的存储和读取
- DataStruct.py 原始软件度量的数据结构
- OPS_DataStruct.py 外部观测的软件度量
- DataStructOfCodeStatsData.py: 定义代码库统计信息的数据结构体
- GenerateCodeStatsData.py: 利用Joern框架生成统计数据。
- CodebaseStatsInfo.xml: 存储统计数据的格式化文件，考虑用xml文件格式，看python对xml的支持程度。
- LoadStatsFileToStruct.py： 将代码库数据分析文件载入结构体中。
- StoreStatsDataToFile.py： 将内存中的结构体数据存入数据文件中。
- PrettyOutputStatsFile-1.py: 以自格式1输出数据文件，可以将文件载如结构体，再格式化输出。
- steps： 自定义的Joern交互脚本
    - CalleeInfo.groovy 获取结构化数据。
- DBContentsProvider.py: 提供基本的Joern查询接口
- GenCodeStatsData.py:  获取代码库的统计数据
2. statsAnalysis： 对原始数据的处理
- plot.py 画图
- convert2vector.py 将原始数据转换为特征向量
- xpoint.py: 安全敏感函数的特征分析
- machinelearning.py 各种分类聚类方法
3. README.md: 项目说明文件

