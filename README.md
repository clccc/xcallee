### 项目说明
1. 名称：xcallee
2. 目的：通过比较参数敏感型函数的不同调用实例的参数约束，采用信息熵度量其差异性，将异常的调用实例推断为存在缺陷的调用实例
3. 实现平台：基于joern平台
4. 时间：2019年01月
5. 作者：cl

使用说明：
0: 总的入口为xcallee.py,直接执行有命令提示信息。两种模式：
    a，输入为安全敏感函数的名称；
    b，输入为extract_args_check_patterns的执行后保存的数据文件。

1. extract_args_check_patterns.py 输入需要提取的安全敏感函数名，从cpg中提取其检查信息并存入相应文件中，以供后续分析。有单thread和多thread模式
2. display_data.py 输入entropy,打印entropy信息
3. calculate_pattern_entropy，根据检查信息计算相应的entropy

更新：
1. 添加显式约束
