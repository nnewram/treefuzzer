import angr

class Fuzzer:
    def __init__(self, entryTree, functionTrees, functionOffsets, binaryPath, auto_load_libs=False):
        self.entryTree = entryTree
        self.functionTrees = functionTrees
        self.functionOffsets = functionOffsets
    
        self.project = angr.Project(binaryPath, auto_load_libs=auto_load_libs)
        self.state = self.project.factory.blank_state()

    def reachable(self, state, goal):
        pass

    def fuzz(self):
        print(self.entryTree.children)