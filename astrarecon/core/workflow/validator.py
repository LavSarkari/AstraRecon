"""Workflow Validation and Linting."""

from typing import Optional
from astrarecon.core.models.workflow import WorkflowDefinition
from astrarecon.core.workflow.graph import WorkflowGraph, WorkflowGraphError


class WorkflowValidationError(Exception):
    """Raised when a workflow fails structural or type validation."""
    pass


class WorkflowValidator:
    """Validates workflow graph consistency, acyclicity, and port contracts."""

    @classmethod
    def validate(cls, workflow: WorkflowDefinition) -> WorkflowGraph:
        """Validates the workflow definition and returns a compiled WorkflowGraph.
        
        Raises WorkflowValidationError on any integrity or topology errors.
        """
        if not workflow.nodes:
            raise WorkflowValidationError(f"Workflow '{workflow.id}' must contain at least one node")

        # Check unique node IDs
        seen_ids = set()
        for node in workflow.nodes:
            if not node.id or not node.id.strip():
                raise WorkflowValidationError("All nodes must have a non-empty 'id'")
            if node.id in seen_ids:
                raise WorkflowValidationError(f"Duplicate node ID detected: '{node.id}'")
            seen_ids.add(node.id)

        # Check edge endpoints exist
        for idx, edge in enumerate(workflow.edges):
            if edge.source not in seen_ids:
                raise WorkflowValidationError(
                    f"Edge #{idx} references non-existent source node '{edge.source}'"
                )
            if edge.target not in seen_ids:
                raise WorkflowValidationError(
                    f"Edge #{idx} references non-existent target node '{edge.target}'"
                )
            if edge.source == edge.target:
                raise WorkflowValidationError(
                    f"Self-referential edge detected on node '{edge.source}'"
                )

        try:
            graph = WorkflowGraph(workflow)
            # Verify acyclicity via topological sort
            graph.topological_sort()
            return graph
        except WorkflowGraphError as err:
            raise WorkflowValidationError(f"Workflow '{workflow.id}' topology error: {str(err)}") from err
