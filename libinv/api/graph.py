import logging

import networkx as nx
from flask import Blueprint
from flask import jsonify
from flask import render_template
from flask import request
from pyvis.network import Network

from libinv.blast_radius.cdx import cdx_to_graph
from libinv.blast_radius.cdx import fetch_cdx_from_s3
from libinv.blast_radius.cdx import minify_package_url

logger = logging.getLogger(__name__)

blastradius = Blueprint("blastradius", __name__, template_folder="templates")


def get_graph(data, child_package):
    parent_package = data["metadata"]["component"]["purl"]
    graph = cdx_to_graph(parent_package, data)

    # Find all paths from parent_package to child_package
    all_paths = list(nx.all_simple_paths(graph, source=parent_package, target=child_package))
    if not all_paths:
        logger.warning("No paths found from parent to child.")
    else:
        logger.info("Paths found: %s", all_paths)

    # Ensure to include the parent node in the subgraph nodes set
    subgraph_nodes = {parent_package}
    for path in all_paths:
        subgraph_nodes.update(path)

    subgraph = graph.subgraph(subgraph_nodes)

    nt = Network(
        "900px",
        "100%",
        select_menu=True,
        directed=True,
        neighborhood_highlight=True,
        cdn_resources="remote",
    )
    nt.toggle_physics(True)
    nt.from_nx(subgraph)

    for node in nt.nodes:
        if child_package in node.get("id"):
            node.update(color="#ff0000")

        node.update(label=minify_package_url(node.get("id")), title=node.get("id"))

    if parent_package in subgraph_nodes:
        nt.get_node(parent_package).update(color="#14452f")
    else:
        logger.warning(
            "Parent node (%s) not in subgraph nodes: %s", parent_package, subgraph_nodes
        )

    # nt.inherit_edge_colors(True)
    nt.get_node(child_package).update(color="#FF0000")
    response = nt.generate_html()
    return response


@blastradius.route("/", methods=["GET"])
def index():
    package = request.args.get("child_package")
    return render_template("graph_index.html", package=package)


@blastradius.route("/generate_graph", methods=["GET"])
def get_graph_api():
    project_name = request.args.get("project_name")
    child_package = request.args.get("child_package")

    if project_name and child_package:
        project_name = project_name[:36] + "/" + project_name[36:-9] + ".sbom.cdx.json"
        data = fetch_cdx_from_s3(project_name)
        return get_graph(data, child_package)
    else:
        return jsonify({"error": "Project name not provided in the request"}), 400


@blastradius.route("/sbom", methods=["GET"])
def get_sbom():
    project_name = request.args.get("project_name")

    if project_name:
        project_name = project_name + ".sbom.cdx.json"
        data = fetch_cdx_from_s3(project_name)
        return data

    return jsonify({"error": "Project name not provided in the request"}), 400
