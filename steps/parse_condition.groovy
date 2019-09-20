Object.metaClass.parseControl= { control, nextCfgId ->
    try {
        //Protected code
        operator = g.v(control).outE('IS_AST_PARENT').inV.operator.toList()
        if (operator.size() == 1)
            operator_code = operator[0]
        else{
            operator_code = " "
        }
        flowlabel_code = _getFlowlabelOfCfgIds(control, nextCfgId)
        children = g.v(control).outE('IS_AST_PARENT').inV.out.transform{
            [it.code, it.type]
        }
        return [flowlabel_code, operator_code, children]
    } catch(Exception ex) {
        //Catch block
        println "parseControl failed: "
        println control
        println nextCfgId
    }

}

// Todo: is it right?
Object.metaClass._getFlowlabelOfCfgIds= { id_first, id_next ->
    try {
        edge = g.v(id_first).outE('FLOWS_TO').id.toList()
        // println edge.size()
        for (i = 0; i < edge.size(); i++) {
            if (g.e(edge[i]).inV.id._().toList()[0] == id_next) {
                // println g.e(edge[i]).flowLabel
                return g.e(edge[i]).flowLabel
            }
        }
        return 'Not found'
    } catch(Exception ex) {
        println "_getFlowlabelOfCfgIds failed: "
        println id_first
        println id_next
    }
}

