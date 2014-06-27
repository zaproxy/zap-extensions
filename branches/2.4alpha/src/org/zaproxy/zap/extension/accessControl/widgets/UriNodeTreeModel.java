package org.zaproxy.zap.extension.accessControl.widgets;

import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ParameterParser;

public class UriNodeTreeModel extends DefaultTreeModel {

	private static final long serialVersionUID = 688700980476792716L;
	private static final Logger log = Logger.getLogger(UriNodeTreeModel.class);

	public UriNodeTreeModel(TreeNode root) {
		super(root);
	}

	public UriNode addPath(Context context, URI uri, String method) {
		Collection<String> urlParams = null;
		try {
			urlParams = context.getUrlParamParser().parse(uri.getQuery()).keySet();
		} catch (URIException e) {
		}
		return addPath(context, uri, method, urlParams, null, null);
	}

	public UriNode addPath(Context context, URI uri, String method, Collection<String> urlParameters,
			Collection<String> formParameters, String contentType) {
		log.debug("addPath " + uri.toString());

		UriNode parent = (UriNode) getRoot();
		UriNode leaf = null;
		String pathSegment = "";
		URI pathSegmentUri;

		try {

			URI hostUri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort());
			String hostname = UriUtils.getHostName(uri);

			// add host
			parent = findOrAddPathSegmentNode(parent, hostname, hostUri);

			ParameterParser paramParser = context.getUrlParamParser();
			List<String> path = paramParser.getTreePath(uri);
			for (int i = 0; i < path.size(); i++) {
				pathSegment = path.get(i);
				if (pathSegment != null && !pathSegment.equals("")) {
					if (i == path.size() - 1) {
						String leafName = UriUtils.getLeafNodeRepresentation(pathSegment, method,
								urlParameters, formParameters, contentType);
						leaf = findOrAddPathSegmentNode(parent, leafName, uri);
					} else {
						pathSegmentUri = new URI(hostUri, paramParser.getAncestorPath(uri, i + 1), false);
						parent = findOrAddPathSegmentNode(parent, pathSegment, pathSegmentUri);
					}
				}
			}
			if (leaf == null) {
				// No leaf found, which means the parent was really the leaf
				// The parent will have been added with a 'blank' href, so replace it with the real
				// one
				log.warn("Why is this warning here??????");
				leaf = parent;
			}

		} catch (Exception e) {
			// ZAP: Added error
			log.error("Exception adding " + uri.toString() + " " + e.getMessage(), e);
		}

		return leaf;
	}

	private UriNode findOrAddPathSegmentNode(UriNode parent, String nodeName, URI path) {
		// ZAP: Added debug
		log.debug("findOrAddPathSegmentNode " + parent.getNodeName() + " / " + nodeName);
		UriNode result = findChild(parent, nodeName);

		// If we don't already have a path node for the given name, create it now
		if (result == null) {
			result = new UriNode(nodeName, path);

			// Find the position to insert the child note so that it keeps alphabetical ordering
			int pos = parent.getChildCount();
			for (int i = 0; i < parent.getChildCount(); i++) {
				UriNode child = (UriNode) parent.getChildAt(i);
				if (child.getNodeName().compareTo(nodeName) < 0) {
					pos = i;
					break;
				}
			}
			insertNodeInto(result, parent, pos);
		}
		return result;
	}

	private UriNode findChild(UriNode parent, String nodeName) {
		@SuppressWarnings("unchecked")
		Enumeration<UriNode> children = parent.children();

		while (children.hasMoreElements()) {
			UriNode child = children.nextElement();
			if (child.getNodeName().equals(nodeName)) {
				log.debug("Found child in parent " + parent.getNodeName() + ": " + nodeName);
				return child;
			}
		}
		log.debug("Did not find child in parent " + parent.getNodeName() + ": " + nodeName);
		return null;
	}
}
