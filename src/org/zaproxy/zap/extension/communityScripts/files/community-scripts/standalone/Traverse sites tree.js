// This script traverses the sites tree - change it to do whatever you want to do :)
//
// Standalone scripts have no template.
// They are only evaluated when you run them. 

function listChildren(node, level) {
    var indentation = "";
    for (var i=0;i<level;i++) indentation += "    ";
    for (var j=0;j<node.getChildCount();j++) {
        print(indentation + node.getChildAt(j).getNodeName());
        listChildren(node.getChildAt(j), level+1);
    }
}

root = org.parosproxy.paros.model.Model.getSingleton().
        getSession().getSiteTree().getRoot();

listChildren(root, 0);


