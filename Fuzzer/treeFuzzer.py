import angr
from CONFIG import *

class Fuzzer:
    def __init__(self, entryTree, functionTrees, functionOffsets, binaryPath, auto_load_libs=False):
        self.entryTree = entryTree
        self.functionTrees = functionTrees
        self.functionOffsets = functionOffsets
    
        self.project = angr.Project(binaryPath, auto_load_libs=auto_load_libs)
        self.state = self.project.factory.blank_state()
        self.simulation_manager = self.project.factory.simulation_manager(self.state)
        self.states = {}
        
    def reuseState(self):
        self.simulation_manager.move('found', 'active')

    def setState(self, state):
        if self.simulation_manager.active:
            self.simulation_manager.move('active', 'deadended')
        self.simulation_manager.populate('active', [state])

    def reachable(self, state, goal, avoid=0):
        self.simulation_manager.explore(find=goal, avoid=avoid)
        if self.simulation_manager.found:
            self.reuseState()
            return self.simulation_manager.found
        return False

    def evaluateBranch(self, state, branch):
        branchTup = branch.name
        if len(branchTup) == 2:
            a = self.reachable(state.copy(), branchTup[0])
            b = self.reachable(state.copy(), branchTup[1], nextInstruction(branchTup[1]))
            if a and b:
                return a
            return a or b
        elif type(branchTup[2]) == str:
            return self.evaluateFunctionCall(state.copy(), branchTup)
        elif type(branchTup[2]) == URETURN:
            return self.reachable(state.copy(), branchTup[0])
        elif type(branchTup[2]) == UJUMP:
            a = self.reachable(state.copy(), branchTup[0])
            b = self.reachable(state.copy(), branchTup[1])
            if a and b:
                return [a, b]
            return a or b
        
    def evaluateFunctionCall(self, state, branchTup):
        for branch in self.functionTrees[branchTup[2]].children:
            self.evaluateBranch(state, branch)
    
    def fuzz(self):
        for child in self.entryTree.children:
            print(child)
            res = self.evaluateBranch(self.state, child)
            print(res)
