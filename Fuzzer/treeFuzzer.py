import angr

class Fuzzer:
    def __init__(self, entryTree, functionTrees, functionOffsets, binaryPath, auto_load_libs=False):
        self.entryTree = entryTree
        self.functionTrees = functionTrees
        self.functionOffsets = functionOffsets
    
        self.project = angr.Project(binaryPath, auto_load_libs=auto_load_libs)
        self.state = self.project.factory.blank_state()
        self.simulation_manager = self.project.factory.simulation_manager()

    def reachable(self, state, goal):
        self.simulation_manager.active = [state]
        self.simulation_manager.explore(find=goal)
        if self.simulation_manager.found:
            return self.simulation_manager.found[-1]
        return False

    def evaluateBranch(self, branch):
        branchTup = branch.name
        if len(branchTup) == 2:
            self.reachable(branchTup[0])

    def fuzz(self):
        for child in self.entryTree.children:
            self.evaluateBranch(child)
