import sys
import re
import subprocess
from itertools import chain
from CONFIG import *

dissasembly = None
functionNames = None
functionOffsets = {}
visited = set()

class CodeFunction:
    def __init__(self, name,  start, end, branches=[]):
        self.name = name
        self.start = start
        self.end = end
        self.branches = branches

def dissasembleProgram(programName):
    global dissasembly
    
    objdump = subprocess.Popen(["objdump", "-d", programName], stdin=None, stdout=subprocess.PIPE)
    dissasembly = objdump.communicate()[0].decode("utf-8")
    
    functions = {functionName: offset for offset, functionName in re.findall("(.*) <(.*)>:", dissasembly)}    
    return functions

def extractFunction(function, nextFunction):
    return dissasembly[dissasembly.find(f"<{function}>:\n")+1 : dissasembly.find(f"<{nextFunction}>:")].split("\n")[1:-2]

def getFunctionCode(searchName):
    global functionNames

    functionidx = functionNames.index(searchName)
    return extractFunction(searchName, functionNames[functionidx+1])

def getVariousBranches(currentFunctionCode):
    bijoined = "|".join(x for x in branchIdentifiers)
    ujijoined = "|".join(x for x in unconditionalJumpIdentifiers)
    branchregex = f"[ \t]+(.*):.*(?:{bijoined})[ \t]+(.*)[ \t]+<.*>"
    jmpregex = f"[ \t]+(.*):.*(?:{ujijoined})[ \t]+(.*)[ \t]+<.*>"
    returnregex = f"[ \t]+(.*):.*(?:{returnIdentifier})"

    currentFunctionCode = "\n".join(currentFunctionCode)
    return [
            (int(found[0], 16), int(found[1], 16))
            for found in re.findall(branchregex, currentFunctionCode)
        ] + [
            (int(found[0], 16), int(found[1].split("#")[-1], 16), UJUMP)
            for found in re.findall(jmpregex, currentFunctionCode)
            if "+0x" not in found[1]
        ] + [
            (int(found, 16), -1, URETURN)
            for found in re.findall(returnregex, currentFunctionCode)
        ]

def getFunctionCalls(currentFunctionCode):
    cijoined = "|".join(callIdentifiers)

    for loc in currentFunctionCode:
        for copcode in callIdentifiers:
            pos = loc.split("<")[0].find(copcode) # there might be functions with call in it.
            if pos != -1:
                break
        else:
            continue
        
        matches = re.findall(f"[ \t]+(.*):[ \t]+.*(?:{cijoined}.*?)[ \t]+(.*) <(.*)>", loc)
        if matches == []:
            continue
        for match in matches:
            address, functionAddress, functionName = match
            if "+0x" in functionName:
                continue

            if "#" in functionAddress:
                functionAddress = functionAddress.split("#")[1] # an edgecase where we call a function + some offset            
            
            yield int(address, 16), int(functionAddress, 16), functionName

def walkFunctionFindBranches(functionName, currentFunctionCode):
    visited.add(functionName)
    functionCalls = getFunctionCalls(currentFunctionCode)
    branches = getVariousBranches(currentFunctionCode)

    allBranchesInFunction = sorted(list(functionCalls) + branches)
    for alterationInFlow in allBranchesInFunction:
        yield alterationInFlow

        if (
            len(alterationInFlow) == 3
            and alterationInFlow[2] != UJUMP
            and alterationInFlow[2] != URETURN
            and "@" not in alterationInFlow[2] # imported function
            ):
            
            if alterationInFlow[2] not in functionNames: # this is most likely a functionpointer, we still expect this branch to return, (TODO add an artificial return?)
                continue # might add artificial return here in the future

            # this is a function call, recurse trough the called function.
            
            nextFunctionName = alterationInFlow[2]
        
            if nextFunctionName in visited:
                continue # already visited function, no need to analyse its' path again.
        
            nextFunctionCode = getFunctionCode(nextFunctionName)
            yield from walkFunctionFindBranches(nextFunctionName, nextFunctionCode)

def findBranches(functions):
    global functionNames
    functionNames = list(functions)
    mainFunction = getFunctionCode("main")
    return walkFunctionFindBranches("main", mainFunction)

functionOffsets = dissasembleProgram(sys.argv[1])
flattenedTree = findBranches(functionOffsets) # the generated flattened tree.

if '--print' in sys.argv:
    for branch in flattenedTree:
        print(branch)

'''
    Next step is to create a "roadmap" for the fuzzer.
    Since we have all possible branches we can create a datastructure
    which defines the order in which all fuzzing attempts should be taken,
    if we notice that a branch is unreachable, we can then "trim" the children of that node.
    Hence, we have eliminated a path in the tree which then propogates down to all children leaves.

    Consider the following example

    Main---> A \ 
        \       C -> D
         \-> B /     |
             ^-------/
    
    If we notice that path A -> C is impossible for any state,
    We trim this path in such a way that we end up with the following tree

    Main---> A
        \       C -> D
         \-> B /     |
             ^-------/

    We then proceed to walking along B, and we notice that the path B -> C also is impossible,
    we trim this path, and notice that the previous curcuit B->C->D->B->... now separated to C->D->B,
    yet since it is impossible to reach C, since A->C is impossible and B->C is impossible. The program then can be simplified tp

    Main---> A
        \ 
         \-> B
'''



