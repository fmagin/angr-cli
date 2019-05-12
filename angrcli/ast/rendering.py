
from graphviz import Digraph
import random
def render_ast(ast):
    graph = Digraph()
    def render_rec(graph, ast):
        if type(ast) in [int]:
            rand_ident = str(random.randint(1,2**32))
            graph.node(rand_ident, label=hex(ast))
            return rand_ident
        if ast.op == 'BVS' or ast.op == "BVV":
            rand_ident = str(random.randint(1,2**32))
            graph.node(rand_ident, label=ast.__str__())
            return rand_ident
        op_node_ident = str(random.randint(1,2**32))
        graph.node(op_node_ident, label=ast.op)
        for arg in ast.args:
            argnode = render_rec(graph, arg)
            graph.edge(op_node_ident, argnode)
        return op_node_ident
    render_rec(graph, ast)
    return graph

def ast_to_svg(ast):
    g = render_ast()
    g._repr_svg_()