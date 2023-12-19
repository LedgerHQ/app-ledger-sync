from typing import Dict
from typing import TypeVar, Generic, List
T = TypeVar('T')


class IndexedTree(Generic[T]):
    def __init__(self, node=None, children: Dict[int, 'IndexedTree'] = None):
        self.node = node
        self.children = children if children is not None else {}

    def get_children(self):
        return self.children

    def get_child(self, index):
        return self.children.get(index)

    def find_child(self, path):
        if len(path) == 0:
            return self

        index = path[0]
        rest = path[1:]

        if index in self.children:
            return self.children[index].find_child(rest)
        return None

    def get_value(self) -> T:
        return self.node

    def update_child(self, path, value):
        if len(path) == 0:
            return IndexedTree(value, self.children)

        index = path[0]
        rest = path[1:]
        children = self.children.copy()

        if index in children:
            sub_tree = children[index].update_child(rest, value)
            children[index] = sub_tree
        else:
            sub_tree = IndexedTree().update_child(rest, value)
            children[index] = sub_tree

        return IndexedTree(self.node, children)

    def add_child(self, path, child):
        if len(path) == 0:
            return self
        if len(path) == 1:
            children = self.children.copy()
            children[path[0]] = child
            return IndexedTree(self.node, children)

        index = path[0]
        rest = path[1:]
        children = self.children.copy()
        if index in self.children:
            sub_tree = self.children[index].add_child(rest, child)
            children[index] = sub_tree
        else:
            sub_tree = IndexedTree().add_child(rest, child)
            children[index] = sub_tree
        return IndexedTree(self.node, children)
