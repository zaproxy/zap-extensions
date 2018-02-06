// Find the largest sub tree under the node the script was invoked with.
// Also reports the total number of sub nodes.
// Targeted scripts can only be invoked by you, the user, eg via a right-click option on the Sites or History tabs

tot = 0
maxparent = ""
maxsub = 0

function recurseDown(node) {
	//print('recurseDown node: ' + node.getHierarchicNodeName() + " " + node.getChildCount())
	tot++
	if (node.getChildCount() > maxsub) {
		maxsub = node.getChildCount();
		maxparent = node.getHierarchicNodeName()
	}
	var j;
	for (j=0;j<node.getChildCount();j++) {
		recurseDown(node.getChildAt(j))
	}
}


function invokeWith(msg) {
	// Debugging can be done using print like this
	//print('invokeWith called for url=' + msg.getRequestHeader().getURI().toString())

	sitestree = org.parosproxy.paros.model.Model.getSingleton().getSession().getSiteTree()
	node = sitestree.findNode(msg, true)

	if (node != null) {
		//print('found node: ' + node.getHierarchicNodeName())
		recurseDown(node)
		tot -- // to remove the top node

		print('Largest subtree under ' + node.getHierarchicNodeName() + ' is')
		print('\t' + maxparent)
		print('With ' + maxsub + ' immediate sub nodes')
		print('Total number of sub nodes = ' + tot)

	} else {
		print('Failed to find node:( ')
	}

}
