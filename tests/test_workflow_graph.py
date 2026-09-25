"""Unit tests for DAG topological sorting, cycle detection, and frontier scheduling."""

import pytest
from astrarecon.core.models.workflow import EdgeDefinition, NodeDefinition, WorkflowDefinition
from astrarecon.core.workflow.graph import CycleDetectedError, WorkflowGraph
from astrarecon.core.workflow.validator import WorkflowValidationError, WorkflowValidator


def test_linear_dag_topological_sort():
    """Validates that a linear chain is sorted in exact execution order."""
    wf = WorkflowDefinition(
        id="linear-test",
        name="Linear Test",
        nodes=[
            NodeDefinition(id="target", type="builtin.target_input"),
            NodeDefinition(id="subfinder", type="plugin.subfinder"),
            NodeDefinition(id="dnsx", type="plugin.dnsx"),
            NodeDefinition(id="httpx", type="plugin.httpx"),
        ],
        edges=[
            EdgeDefinition(source="target", source_port="domain", target="subfinder", target_port="target"),
            EdgeDefinition(source="subfinder", source_port="subdomains", target="dnsx", target_port="hosts"),
            EdgeDefinition(source="dnsx", source_port="valid_hosts", target="httpx", target_port="targets"),
        ],
    )

    graph = WorkflowValidator.validate(wf)
    order = graph.topological_sort()
    assert order == ["target", "subfinder", "dnsx", "httpx"]

    tiers = graph.get_execution_tiers()
    assert len(tiers) == 4
    assert tiers[0] == ["target"]
    assert tiers[1] == ["subfinder"]
    assert tiers[2] == ["dnsx"]
    assert tiers[3] == ["httpx"]


def test_subdomain_fan_in_topology():
    """Validates multi-source fan-in: 4 concurrent tools converging to union dedupe."""
    wf = WorkflowDefinition(
        id="fan-in-test",
        name="Fan-in Test",
        nodes=[
            NodeDefinition(id="target", type="builtin.target_input"),
            NodeDefinition(id="subfinder", type="plugin.subfinder"),
            NodeDefinition(id="assetfinder", type="plugin.assetfinder"),
            NodeDefinition(id="amass", type="plugin.amass"),
            NodeDefinition(id="subenum", type="plugin.subenum"),
            NodeDefinition(id="dedupe", type="builtin.union_dedupe"),
            NodeDefinition(id="dnsx", type="plugin.dnsx"),
        ],
        edges=[
            EdgeDefinition(source="target", source_port="domain", target="subfinder", target_port="target"),
            EdgeDefinition(source="target", source_port="domain", target="assetfinder", target_port="target"),
            EdgeDefinition(source="target", source_port="domain", target="amass", target_port="target"),
            EdgeDefinition(source="target", source_port="domain", target="subenum", target_port="target"),
            EdgeDefinition(source="subfinder", source_port="subdomains", target="dedupe", target_port="inputs"),
            EdgeDefinition(source="assetfinder", source_port="subdomains", target="dedupe", target_port="inputs"),
            EdgeDefinition(source="amass", source_port="subdomains", target="dedupe", target_port="inputs"),
            EdgeDefinition(source="subenum", source_port="subdomains", target="dedupe", target_port="inputs"),
            EdgeDefinition(source="dedupe", source_port="output", target="dnsx", target_port="hosts"),
        ],
    )

    graph = WorkflowValidator.validate(wf)
    tiers = graph.get_execution_tiers()
    
    # Tier 0: target
    assert tiers[0] == ["target"]
    # Tier 1: the 4 parallel enumeration tools
    assert set(tiers[1]) == {"subfinder", "assetfinder", "amass", "subenum"}
    # Tier 2: dedupe (waits for all 4)
    assert tiers[2] == ["dedupe"]
    # Tier 3: dnsx
    assert tiers[3] == ["dnsx"]


def test_cycle_detection():
    """Validates that circular dependencies are caught and rejected."""
    wf = WorkflowDefinition(
        id="cycle-test",
        name="Cycle Test",
        nodes=[
            NodeDefinition(id="node_a", type="test"),
            NodeDefinition(id="node_b", type="test"),
            NodeDefinition(id="node_c", type="test"),
        ],
        edges=[
            EdgeDefinition(source="node_a", source_port="out", target="node_b", target_port="in"),
            EdgeDefinition(source="node_b", source_port="out", target="node_c", target_port="in"),
            EdgeDefinition(source="node_c", source_port="out", target="node_a", target_port="in"),  # Cycle!
        ],
    )

    with pytest.raises(WorkflowValidationError) as exc_info:
        WorkflowValidator.validate(wf)
    assert "Circular dependency" in str(exc_info.value)


def test_ready_frontier_progression():
    """Validates that get_ready_frontier properly tracks completed node sets."""
    wf = WorkflowDefinition(
        id="frontier-test",
        name="Frontier Test",
        nodes=[
            NodeDefinition(id="seed", type="seed"),
            NodeDefinition(id="branch_1", type="worker"),
            NodeDefinition(id="branch_2", type="worker"),
            NodeDefinition(id="collector", type="join"),
        ],
        edges=[
            EdgeDefinition(source="seed", source_port="out", target="branch_1", target_port="in"),
            EdgeDefinition(source="seed", source_port="out", target="branch_2", target_port="in"),
            EdgeDefinition(source="branch_1", source_port="out", target="collector", target_port="in"),
            EdgeDefinition(source="branch_2", source_port="out", target="collector", target_port="in"),
        ],
    )

    graph = WorkflowValidator.validate(wf)

    # Initial state: only 'seed' is ready
    ready = graph.get_ready_frontier(completed_node_ids=set(), in_flight_node_ids=set())
    assert ready == ["seed"]

    # When seed is running (in-flight), nothing new is ready
    ready = graph.get_ready_frontier(completed_node_ids=set(), in_flight_node_ids={"seed"})
    assert ready == []

    # When seed completes, branch_1 and branch_2 become ready
    ready = graph.get_ready_frontier(completed_node_ids={"seed"}, in_flight_node_ids=set())
    assert set(ready) == {"branch_1", "branch_2"}

    # When branch_1 completes but branch_2 is in-flight, collector is NOT ready yet
    ready = graph.get_ready_frontier(completed_node_ids={"seed", "branch_1"}, in_flight_node_ids={"branch_2"})
    assert ready == []

    # When both branch_1 and branch_2 complete, collector becomes ready
    ready = graph.get_ready_frontier(completed_node_ids={"seed", "branch_1", "branch_2"}, in_flight_node_ids=set())
    assert ready == ["collector"]


def test_fan_in_partial_failure_tolerance():
    """Validates that multi-source aggregator nodes execute when partial inputs succeed."""
    wf = WorkflowDefinition(
        id="fault-tolerance-test",
        name="Fault Tolerance Test",
        nodes=[
            NodeDefinition(id="target", type="builtin.target_input"),
            NodeDefinition(id="subfinder", type="plugin.subfinder"),
            NodeDefinition(id="assetfinder", type="plugin.assetfinder"),
            NodeDefinition(id="union_dedupe", type="builtin.union_dedupe"),
            NodeDefinition(id="dnsx", type="plugin.dnsx"),
        ],
        edges=[
            EdgeDefinition(source="target", source_port="domain", target="subfinder", target_port="target"),
            EdgeDefinition(source="target", source_port="domain", target="assetfinder", target_port="target"),
            EdgeDefinition(source="subfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
            EdgeDefinition(source="assetfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
            EdgeDefinition(source="union_dedupe", source_port="output", target="dnsx", target_port="hosts"),
        ],
    )

    graph = WorkflowValidator.validate(wf)

    # Initial state
    ready = graph.get_ready_frontier(completed_node_ids=set(), in_flight_node_ids=set())
    assert ready == ["target"]

    # Target completes -> both subdomain tools ready
    ready = graph.get_ready_frontier(completed_node_ids={"target"}, in_flight_node_ids=set())
    assert set(ready) == {"subfinder", "assetfinder"}

    # Subfinder completes, but Assetfinder fails:
    # union_dedupe should still be scheduled because it has 1 valid input!
    ready = graph.get_ready_frontier(
        completed_node_ids={"target", "subfinder"},
        in_flight_node_ids=set(),
        failed_node_ids={"assetfinder"},
    )
    assert ready == ["union_dedupe"]

    # Once union_dedupe completes, dnsx runs normally
    ready = graph.get_ready_frontier(
        completed_node_ids={"target", "subfinder", "union_dedupe"},
        in_flight_node_ids=set(),
        failed_node_ids={"assetfinder"},
    )
    assert ready == ["dnsx"]
