// Remove all nodes that match the specified criteria from the Sites tree under the node
// the script was invoked with.
// The default criteria is leaf nodes with a response code of 302 but you can change that to anything you need
// Targeted scripts can only be invoked by you, the user, eg via a right-click option on the Sites or History tabs

function recurseDown(sitestree, node) {
	//println('recurseDown node: ' + node.getHierarchicNodeName() + " " + node.getChildCount())
	// Loop down through the children first
	var j;
	for (j=0;j<node.getChildCount();j++) {
		if (recurseDown(sitestree, node.getChildAt(j))) {
			// just removed the child
			j--
		}
	}
	if (deleteThis(node)) {
		println('Removing node: ' + node.getHierarchicNodeName())
		org.zaproxy.zap.extension.history.PopupMenuPurgeSites.purge(sitestree, node)
		return true
	}
	return false
}

function deleteThis(node) {
	// change this to match any other criteria you want!
	if (node.getChildCount() == 0) {
		// only remove child nodes
		href = node.getHistoryReference()
		if (href != null) {
			if (href.getStatusCode() == 302) {
				return true
			}
		}
	}
	return false
}

function invokeWith(msg) {
	// Debugging can be done using println like this
	//println('invokeWith called for url=' + msg.getRequestHeader().getURI().toString())

	sitestree = org.parosproxy.paros.model.Model.getSingleton().getSession().getSiteTree()
	node = sitestree.findNode(msg, true)

	if (node != null) {
		//println('found node: ' + node.getHierarchicNodeName())
		recurseDown(sitestree, node)
	}

}
