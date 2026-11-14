"""Minimal union-find (disjoint set) with path compression."""

from __future__ import annotations


class UnionFind:
    """Union-find over ``0..size-1`` with union by size."""

    __slots__ = ("_parent", "_size", "unions")

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))
        self._size = [1] * size
        self.unions = 0

    def find(self, item: int) -> int:
        parent = self._parent
        root = item
        while parent[root] != root:
            root = parent[root]
        while parent[item] != root:
            parent[item], item = root, parent[item]
        return root

    def union(self, left: int, right: int) -> bool:
        """Merge two sets; returns ``True`` when a merge actually happened."""

        root_left = self.find(left)
        root_right = self.find(right)
        if root_left == root_right:
            return False
        if self._size[root_left] < self._size[root_right]:
            root_left, root_right = root_right, root_left
        self._parent[root_right] = root_left
        self._size[root_left] += self._size[root_right]
        self.unions += 1
        return True

    def connected(self, left: int, right: int) -> bool:
        return self.find(left) == self.find(right)

    def groups(self) -> dict[int, list[int]]:
        """Map root -> member indexes."""

        grouped: dict[int, list[int]] = {}
        for item in range(len(self._parent)):
            grouped.setdefault(self.find(item), []).append(item)
        return grouped

    def __len__(self) -> int:
        return len(self._parent)
