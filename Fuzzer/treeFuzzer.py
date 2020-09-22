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
        
        self.reached = []
        self.unreachable = []
        self.visitedFunctionsStates = {} # function : state, when recursion, if state1 != state2, high chance stop recursive, else not stop, dont try

    def reuseState(self):
        self.simulation_manager.move('found', 'active')

    def setState(self, state):
        if self.simulation_manager.active:
            self.simulation_manager.move('active', 'deadended')
        self.simulation_manager.populate('active', [state])

    def reachable(self, state, goal, avoid=0):
        self.setState(state)
        self.simulation_manager.explore(find=goal, avoid=avoid)
        if self.simulation_manager.found:
            self.reuseState()
            self.reached.append(goal)
            return self.simulation_manager.found
        self.unreachable.append(goal)
        return False

    def evaluateBranch(self, state, branch):
        if type(branch) != tuple:
            branchTup = branch.name
        else:
            branchTup = branch
        
        print("branchtup:", branchTup)
        
        if len(branchTup) == 1:
            a = self.reachable(state.copy(), branchTup[0])
            return a
        if len(branchTup) == 2:
            a = self.reachable(state.copy(), branchTup[0])
            b = self.reachable(state.copy(), branchTup[1])
            if a and b:
                return a + b
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
        if branchTup[2] not in self.functionTrees:
            # it is a call to GOT
            print("Evaluating:", branchTup[2])
            entrystate = state.copy()
            print(self.evaluateBranch(entrystate, (branchTup[0], )))
        else:
            if branchTup[2] in self.visitedFunctionsStates:
                if state in self.visitedFunctionsStates[branchTup[2]]:
                    print("Infinite recursion")
                    return
                self.visitedFunctionsStates[branchTup[2]].append(state)
            else:
                self.visitedFunctionsStates[branchTup[2]] = [state]

            for branch in self.functionTrees[branchTup[2]].children:
                entrystate = state.copy()
                print("Evaluating:", branch)
                print(self.evaluateBranch(entrystate, branch))
    
            del self.visitedFunctionsStates[branchTup[2]] # finished recursing the function. --11--

    def fuzz(self):
        for child in self.entryTree.children:
            print(child)
            res = self.evaluateBranch(self.state, child)
            print("Res:", res)

        print("bruh!")
        print("reached:", self.reached)
        print("unreachable:", self.unreachable)