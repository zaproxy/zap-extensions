package org.zaproxy.zap.extension.accessControl.widgets;

import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.model.Context;

public class ContextSiteTree extends SiteTree {

	public ContextSiteTree() {
		super(new SiteTreeNode(Constant.messages.getString("accessControl.contextTree.root"), null));
	}

	public void reloadTree(Session session, Context context) {
		log.debug("Reloading tree for context: " + context.getIndex());
		this.getRoot().removeAllChildren();
		List<SiteNode> contextNodes = session.getNodesInContextFromSiteTree(context);
		for (SiteNode node : contextNodes) {
			HistoryReference ref = node.getHistoryReference();
			if (ref != null)
				this.addPath(context, ref.getURI(), ref.getMethod());
		}
	}

}
