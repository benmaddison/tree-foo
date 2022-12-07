#!/usr/bin/env python
"""Merkle chain for a string value."""
from __future__ import annotations
import hashlib

from typing import Any, Optional, Iterable, List

INIT_HASHER = hashlib.sha256(b"")


class Value:
    _value: Any

    @property
    def digest(self) -> bytes:
        raise NotImplementedError

    def __repr__(self) -> str:
        return self._value.__repr__()


class String(Value):
    def __init__(self, s: str) -> None:
        self._value = s

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self._value.encode()).digest()


class Array(Value):
    def __init__(self, items: Iterable[String]) -> None:
        self._value = list(items)

    @property
    def digest(self) -> bytes:
        hasher = INIT_HASHER.copy()
        for v in self._value:
            hasher.update(v.digest)
        return hasher.digest()


class Node:
    hasher: hashlib._Hash

    def __init__(self, value: Value, parent: Optional[Node] = None) -> None:
        if parent is None:
            self._hasher = INIT_HASHER.copy()
        else:
            self._hasher = parent._hasher.copy()
        self._hasher.update(value.digest)
        self._value = value
        self._parent = parent

    @property
    def hash(self) -> str:
        return self._hasher.hexdigest()

    @property
    def value(self) -> Value:
        return self._value

    def __repr__(self) -> str:
        return f"{self.value}({self.hash})"


class Tree:
    _root: Optional[Node] = None

    @property
    def root(self) -> Optional[Node]:
        return self._root

    def append(self, value: Value) -> None:
        self._root = Node(value, parent=self.root)

    @classmethod
    def from_iter(cls, values: Iterable[Value]) -> Tree:
        tree = cls()
        for v in values:
            tree.append(v)
        return tree

    def __repr__(self) -> str:
        node = self.root
        buf = ""
        while node is not None:
            buf += f"{node} "
            node = node._parent
        return buf.rstrip()

    def verify(self) -> None:
        ancestors: List[Node] = list()
        node = self.root
        while node is not None:
            ancestors.insert(0, node)
            node = node._parent
        hasher = INIT_HASHER.copy()
        for node in ancestors:
            hasher.update(node.value.digest)
        if self.root is not None:
            assert hasher.hexdigest() == self.root.hash


if __name__ == "__main__":
    values = [String("foo"), Array([String("bar"), String("baz")])]
    tree = Tree.from_iter(values)
    print(tree)
    tree.verify()
    print("OK!")

    assert tree.root is not None
    assert tree.root._parent is not None

    tree.root._value._value[0] = String("quux")
    try:
        tree.verify()
    except AssertionError:
        print("corruption detected!")
