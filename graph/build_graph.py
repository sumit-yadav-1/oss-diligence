from langgraph.graph import END, START, StateGraph

from agents.aggregator import aggregator_node
from agents.health_analyst import health_analyst_node
from agents.security_analyst import security_analyst_node
from agents.license_analyst import license_analyst_node
from utils.state import DiligenceState


def build_diligence_graph():
    graph = StateGraph(DiligenceState)

    graph.add_node("health_analyst", health_analyst_node)
    graph.add_node("security_analyst", security_analyst_node)
    graph.add_node("license_analyst", license_analyst_node)
    graph.add_node("aggregator", aggregator_node)

    graph.add_edge(START, "health_analyst")
    graph.add_edge(START, "security_analyst")
    graph.add_edge(START, "license_analyst")

    graph.add_edge("health_analyst", "aggregator")
    graph.add_edge("security_analyst", "aggregator")
    graph.add_edge("license_analyst", "aggregator")

    graph.add_edge("aggregator", END)

    return graph.compile()