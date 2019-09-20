/*
follow the @path,add new id into the path, gen @newpaths
*/
Object.metaClass.getBackwardPaths = { calleeid ->
    cfgid = g.v(calleeid)._().statements().id.toList().toList()[0]
    if(g.v(cfgid).isCFGNode != "True")
    {
        println "error"
        return []
    }
    paths = [[cfgid]]
    newpaths = []
    allpaths = []
    while (paths.size() != 0)
    {
        // println "paths.size() = " + paths.size()
        // println "allpaths.size() = " + allpaths.size()

        newpaths = genNewPaths(paths)
        // if it can not gen new path, have to break loop
        if (newpaths.size ==0)
            break
        i = newpaths.size()-1
        for(;i>=0;i--)
        {
            if( isCompletePath(newpaths[i])){
                allpaths.add(newpaths[i])
                newpaths.remove(i)
            }
        }
        paths = newpaths
        if(paths.size() > 10000){
            println "error"
            return allpaths
        }
    }
    return allpaths
}

Object.metaClass.genNewPaths = { paths ->
    def newpaths = []
    for(xpath in paths){
        lastid = xpath[xpath.size()-1]
        newids = g.v(lastid).inE('label','FLOWS_TO').outV.id.toList()
        for(xid in newids){
            //if count(xid) >= 2, the xpath has looped 2 times, it must be deleted,and remove this loop path
            counts = countIDs(xpath,xid)
            if (counts >=2){
                flag_invalid = true
                continue
            }
            new_path = xpath.plus(xid)
            newpaths.add(new_path)
        }
    }
    newpaths.unique()
    return newpaths
}

Object.metaClass.countIDs = { path,xid ->
    count = 0
    for(id in path)
    {
        if(xid == id)
            count = count +1
    }
    return count
}

/*
check the @path,remove the loop path and  save the complete path in to @allpaths
*/
Object.metaClass.isCompletePath = { path ->
//if the lastid.code = 'ENTRY', the path is a complete path, save it into @allpaths
    if(g.v(path[path.size()-1]).code == "ENTRY"){
        return true
    }
//else pass
    return false
}

Object.metaClass.printpath = { path ->
    for(id in path)
    {
        print "id = " + id
        print g.v(id).code
        print " -> "
    }
    println "end /n"
}