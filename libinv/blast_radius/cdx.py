import json

import networkx as nx

from libinv.env import S3_BUCKET_NAME
from libinv.helpers import get_boto3_client


def fetch_cdx_from_s3(project_name):
    s3 = get_boto3_client("s3")
    response = s3.get_object(Bucket=S3_BUCKET_NAME, Key=project_name)
    file_content = response["Body"].read().decode("utf-8")
    return json.loads(file_content)


def cdx_to_graph(parent, cdx):
    """
    Convert CDX data to a directed graph
    """
    components = cdx.get("components", [])
    dependencies = cdx.get("dependencies", [])
    G = nx.DiGraph()
    G.add_node(parent)
    for component in components:
        name = component.get("bom-ref")
        G.add_node(name)

    for dependency in dependencies:
        ref = dependency.get("ref")
        depends_on = dependency.get("dependsOn", [])
        for dep in depends_on:
            G.add_edge(ref, dep)

    return G


def minify_package_url(package):
    return package.split("/")[-1].replace("?type=jar", "")
