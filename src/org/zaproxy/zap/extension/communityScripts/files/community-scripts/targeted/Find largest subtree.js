// Find the largest sub tree under the node the script was invoked with.
// Also reports the total number of sub nodes.
// Targeted scripts can only be invoked by you, the user, eg via a right-click option on the Sites or History tabs

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

tot = 0
maxparent = ""
maxsub = 0

function recurseDown(node) {
	//println('recurseDown node: ' + node.getHierarchicNodeName() + " " + node.getChildCount())
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
	// Debugging can be done using println like this
	//println('invokeWith called for url=' + msg.getRequestHeader().getURI().toString())

	sitestree = org.parosproxy.paros.model.Model.getSingleton().getSession().getSiteTree()
	node = sitestree.findNode(msg, true)

	if (node != null) {
		//println('found node: ' + node.getHierarchicNodeName())
		recurseDown(node)
		tot -- // to remove the top node

		println('Largest subtree under ' + node.getHierarchicNodeName() + ' is')
		println('\t' + maxparent)
		println('With ' + maxsub + ' immediate sub nodes')
		println('Total number of sub nodes = ' + tot)

	} else {
		println('Failed to find node:( ')
	}

}
