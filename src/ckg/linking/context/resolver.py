from ckg.domain.entities.context import ContextFacet
from ckg.graph.models import GraphNode
from ckg.linking.context.normalizer import NormalizedContext


def context_node(context: NormalizedContext) -> GraphNode:
    facet = ContextFacet(context_id=context.context_id, kind=context.kind, name=context.name)
    return GraphNode(label=context.kind, node_id=context.context_id, props=facet.model_dump(mode="json"))
