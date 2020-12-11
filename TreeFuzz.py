import sys
import re # python regex library
import subprocess # python library for executing commands
from itertools import chain # used to "chain" two lists/generators etc into one
from CONFIG import * # load the configuration profile from CONFIG.py
from types import GeneratorType # comparing generator type
from anytree import Node, RenderTree # tree strucure to represent the program

import Fuzzer.treeFuzzer

dissasembly = None
functionNames = None
functionOffsets = {}
visited = set() # we use a set for O(1) lookup
pieOffset = 0

functionNodes = {} # we use this to map function name -> subtree, in order to be able to support recursion without creating an infinite tree

def dissasembleProgram(programName: str):
    global dissasembly, pieOffset
    
    objdump = subprocess.Popen(["objdump", "-d", programName], stdin=None, stdout=subprocess.PIPE)
    dissasembly = objdump.communicate()[0].decode("utf-8")
    
    pie = re.search("(.*) <(.*)>:", dissasembly).groups()[0]
    if int(pie, 16) < pieConfigOffset:
        pieOffset = pieConfigOffset

    functions = {functionName: int(offset, 16) + pieOffset for offset, functionName in re.findall("(.*) <(.*)>:", dissasembly)}    
    return functions

def extractFunction(function, nextFunction):
    return dissasembly[dissasembly.find(f"<{function}>:\n")+1 : dissasembly.find(f"<{nextFunction}>:")].split("\n")[1:-2]

def getFunctionCode(searchName):
    global functionNames

    functionidx = functionNames.index(searchName)
    return extractFunction(searchName, functionNames[functionidx+1])

def getVariousBranches(caller, currentFunctionCode):
    '''
    Regex find all 
        *branching(conditional)
        *jumping(conditional)
        *returning(unconditional)
    instructions such as je (jump equal), jmp (jump), retq (return)
    then return a list of all these instructions and their offset
    '''
    bijoined = "|".join(x for x in branchIdentifiers)
    ujijoined = "|".join(x for x in unconditionalJumpIdentifiers)
    branchregex = f"[ \t]+(.*):.*(?:{bijoined})[ \t]+(.*)[ \t]+<.*>"
    jmpregex = f"[ \t]+(.*):.*(?:{ujijoined})[ \t]+(.*)[ \t]+<.*>"
    returnregex = f"[ \t]+(.*):.*(?:{returnIdentifier})"

    currentFunctionCode = "\n".join(currentFunctionCode)
    return [
            (int(found[0], 16) + pieOffset, int(found[1], 16) + pieOffset)
            for found in re.findall(branchregex, currentFunctionCode)
        ] + [
            (int(found[0], 16) + pieOffset, int(found[1].split("#")[-1], 16) + pieOffset, UJUMP)
            for found in re.findall(jmpregex, currentFunctionCode)
            if "+0x" not in found[1]
        ] + [
            (int(found, 16) + pieOffset, caller, URETURN)
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
            
            yield int(address, 16) + pieOffset, int(functionAddress, 16) + pieOffset, functionName

def walkFunctionFindBranches(functionName):
    '''
    Recursive function to create a generator object
    which yields all the possible branches in all used functions
    '''
    visited.add(functionName)
    currentFunctionCode = getFunctionCode(functionName)
    functionCalls = getFunctionCalls(currentFunctionCode)
    branches = getVariousBranches(functionName, currentFunctionCode)

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
        
            yield walkFunctionFindBranches(nextFunctionName) # we could use 'yield from walk...' here, however that would flatten our structure and create unnecessery computation

def findBranches(functions):
    '''
    Find all branches in the program, starting at entryPoint as defined in CONFIG, can be overwritten by argv
    '''
    global functionNames, entryPoint
    functionNames = list(functions)
    if '--entry' in sys.argv:
        entryPoint = sys.argv[sys.argv.index('--entry')+1]

    return walkFunctionFindBranches(entryPoint)

def generateTree(branches, root):
    global functionNodes
    prevNode = None
    for branch in branches:
        if type(branch) == GeneratorType:
            functionNodes[prevNode.name[2]] = generateTree(branch, functionNodes[prevNode.name[2]])
        elif len(branch) == 3 and type(branch[2]) == str:
            if branch[2] not in functionNodes and "@plt" not in branch[2]:
                functionNodes[branch[2]] = Node(branch[2])
            prevNode = Node(branch, parent=root)
        else:
            prevNode = Node(branch, parent=root)
    return root

functionOffsets = dissasembleProgram(sys.argv[1])
branches = findBranches(functionOffsets) # the generated flattened tree.

try:
    branchTree = generateTree(branches, Node(functionOffsets[entryPoint]))
except:
    print(functionOffsets)
    exit(0)
    
if '--print' in sys.argv:
    for pre, _, node in RenderTree(branchTree):
        print(f"%s{node.name}" % pre) 
    for func in functionNodes:
        for pre, _, node in RenderTree(functionNodes[func]):
            print(f"%s{node.name}" % pre)
    
    exit()

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

fuzzer = Fuzzer.treeFuzzer.Fuzzer(branchTree, functionNodes, functionOffsets, sys.argv[1])
fuzzer.fuzz()
