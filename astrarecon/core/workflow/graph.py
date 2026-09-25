"""Directed Acyclic Graph (DAG) Topology, Cycle Detection, and Topological Sorting."""

from collections import defaultdict, deque
from typing import Optional

from astrarecon.core.models.workflow import EdgeDefinition, NodeDefinition, WorkflowDefinition


class WorkflowGraphError(Exception):
    """Base exception for workflow graph errors."""
    pass


class CycleDetectedError(WorkflowGraphError):
    """Raised when a circular dependency is detected in the workflow."""
    pass


class InvalidEdgeError(WorkflowGraphError):
    """Raised when an edge references an unknown node or port."""
    pass


class WorkflowGraph:
    """Manages the in-memory DAG representation and dependency scheduling."""

    def __init__(self, workflow: WorkflowDefinition):
        self.workflow = workflow
        self.nodes: dict[str, NodeDefinition] = {}
        self.in_edges: dict[str, list[EdgeDefinition]] = defaultdict(list)
        self.out_edges: dict[str, list[EdgeDefinition]] = defaultdict(list)
        self.in_degree: dict[str, int] = defaultdict(int)
        
        self._build_graph()

    def _build_graph(self) -> None:
        """Constructs adjacency maps and validates reference integrity."""
        for node in self.workflow.nodes:
            if node.id in self.nodes:
                raise WorkflowGraphError(f"Duplicate node ID '{node.id}' in workflow '{self.workflow.id}'")
            self.nodes[node.id] = node
            self.in_degree[node.id] = 0

        for edge in self.workflow.edges:
            if edge.source not in self.nodes:
                raise InvalidEdgeError(f"Edge source '{edge.source}' does not exist in workflow")
            if edge.target not in self.nodes:
                raise InvalidEdgeError(f"Edge target '{edge.target}' does not exist in workflow")

            self.out_edges[edge.source].append(edge)
            self.in_edges[edge.target].append(edge)
            self.in_degree[edge.target] += 1

    def topological_sort(self) -> list[str]:
        """Returns a valid topological ordering of node IDs using Kahn's algorithm.
        
        Raises CycleDetectedError if the graph contains any cycles.
        """
        in_deg = dict(self.in_degree)
        queue = deque([node_id for node_id, deg in in_deg.items() if deg == 0])
        ordered: list[str] = []

        while queue:
            node_id = queue.popleft()
            ordered.append(node_id)

            for edge in self.out_edges[node_id]:
                target = edge.target
                in_deg[target] -= 1
                if in_deg[target] == 0:
                    queue.append(target)

        if len(ordered) != len(self.nodes):
            unresolved = [node_id for node_id, deg in in_deg.items() if deg > 0]
            raise CycleDetectedError(f"Circular dependency detected involving nodes: {unresolved}")

        return ordered

    def get_execution_tiers(self) -> list[list[str]]:
        """Groups nodes into parallel execution tiers.
        
        Nodes in the same tier can execute concurrently because all their
        dependencies belong to earlier tiers.
        """
        in_deg = dict(self.in_degree)
        queue = deque([node_id for node_id, deg in in_deg.items() if deg == 0])
        tiers: list[list[str]] = []
        visited_count = 0

        while queue:
            current_tier: list[str] = []
            next_queue: deque[str] = deque()

            while queue:
                node_id = queue.popleft()
                current_tier.append(node_id)
                visited_count += 1

                for edge in self.out_edges[node_id]:
                    target = edge.target
                    in_deg[target] -= 1
                    if in_deg[target] == 0:
                        next_queue.append(target)

            tiers.append(current_tier)
            queue = next_queue

        if visited_count != len(self.nodes):
            unresolved = [node_id for node_id, deg in in_deg.items() if deg > 0]
            raise CycleDetectedError(f"Circular dependency detected involving nodes: {unresolved}")

        return tiers

    def get_upstream_node_ids(self, node_id: str) -> set[str]:
        """Returns all immediate upstream predecessor node IDs for a given node."""
        return {edge.source for edge in self.in_edges[node_id]}

    def get_downstream_node_ids(self, node_id: str) -> set[str]:
        """Returns all immediate downstream successor node IDs for a given node."""
        return {edge.target for edge in self.out_edges[node_id]}

    def get_ready_frontier(
        self,
        completed_node_ids: set[str],
        in_flight_node_ids: set[str],
        failed_node_ids: Optional[set[str]] = None,
    ) -> list[str]:
        """Determines which nodes are ready to be scheduled next.
        
        A node is ready if:
        1. It is not already completed, in-flight, or failed.
        2. All of its immediate upstream dependencies have finished (completed or failed).
        3. For aggregator nodes (e.g. union_dedupe or nodes with multiple inputs), at least
           one upstream dependency succeeded with valid output artifacts.
        4. For standard single-input nodes, all upstream dependencies must have completed successfully.
        """
        ready: list[str] = []
        failed = failed_node_ids or set()
        resolved = completed_node_ids | failed

        for node_id, node in self.nodes.items():
            if node_id in completed_node_ids or node_id in in_flight_node_ids or node_id in failed:
                continue

            upstream = self.get_upstream_node_ids(node_id)
            if not upstream:
                ready.append(node_id)
                continue

            # All upstream dependencies must have finished execution (either completed or failed)
            if upstream.issubset(resolved):
                is_aggregator = node.type in ("builtin.union_dedupe", "builtin.merge") or len(upstream) > 1
                if is_aggregator:
                    # At least one upstream dependency completed successfully
                    if any(up in completed_node_ids for up in upstream):
                        ready.append(node_id)
                else:
                    if upstream.issubset(completed_node_ids):
                        ready.append(node_id)

        return ready
