# This script traverses the sites tree - change it to do whatever you want to do :)
#
# Standalone scripts have no template.
# They are only evaluated when you run them.

require 'java'

def listChildren(node, level)
  indent = ""
  for i in 0..level
    indent += "    "
  end
  for j in 0..node.getChildCount()-1
    puts(indent + node.getChildAt(j).getNodeName())
    listChildren(node.getChildAt(j), level+1)
  end
end

root = org.parosproxy.paros.model.Model.getSingleton().getSession().getSiteTree().getRoot();

listChildren(root, 0);


