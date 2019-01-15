Object.metaClass.parseControl= { control, nextCfgId ->
    println "parseControl control = " + control
    operator = g.v(control).outE('IS_AST_PARENT').inV.operator.toList()
    operator_code = ''
    if (operator.size() == 1)
        operator_code = operator[0]
    flowlabel_code = _getFlowlabelOfCfgIds(control, nextCfgId)
    children = g.v(control).outE('IS_AST_PARENT').inV.out.transform{
        [it.code, it.type]
    }
    return [flowlabel_code, operator_code, children]
}

// Todo: is it right?
Object.metaClass._getFlowlabelOfCfgIds= { id_out, id_in ->
    edge = g.v(id_out).outE('FLOWS_TO').id.toList()
    println edge.size()
    for(i=0;i<edge.size();i++){
        if(g.e(edge[i]).inV.id._().toList()[0] == id_in) {
            println g.e(edge[i]).flowLabel
            return g.e(edge[i]).flowLabel
        }
    }
    return 'Not found'
}

Object.metaClass._getOperateOfControlIds = { id ->
    operator = g.v(id).outE('IS_AST_PARENT').inV.operator
    return  operator
}
