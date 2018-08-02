package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public abstract class WebSocketTreeNode implements StructuralWebSocketNode {
    
    private Logger LOGGER = Logger.getLogger(WebSocketTreeNode.class);
    
    protected WebSocketNodeType type;
    protected StructuralWebSocketNode parent = null;
    protected List<StructuralWebSocketNode> children;
    protected String nodeName;
    protected int[] nodeIndex;
    
    WebSocketTreeNode(WebSocketNodeType type, StructuralWebSocketNode parent, String nodeName){
        this.type = type;
        this.children = new ArrayList<>();
        this.nodeName = nodeName;
        addParent(parent);
    }
    
    @Override
    public boolean isRoot() {
        return (parent==null);
    }
    
    @Override
    public StructuralWebSocketNode getParent() {
        return parent;
    }

    @Override
    public List<StructuralWebSocketNode> getChildren() {
        return children;
    }
    
    @Override
    public int getChildCount() {
        return children.size();
    }
    
    @Override
    public void setNodeName(String nodeName) {
        this.nodeName = nodeName;
    }
    
    @Override
    public String getNodeName() {
        return nodeName;
    }
    
    @Override
    public boolean isLeaf(){
        return children.isEmpty();
    }
    
    @Override
    public boolean addChild(StructuralWebSocketNode child) {
        boolean result = false;
        if(!children.contains(child)){
            result = true;
            children.add(child);
    
            int[] childNodeIndex = new int[nodeIndex.length + 1];
            System.arraycopy( nodeIndex, 0, childNodeIndex, 0, nodeIndex.length);
            childNodeIndex[nodeIndex.length] = children.size() - 1;
            
            child.setNodeIndex(childNodeIndex);
            child.addParent(this);
        }
        return result;
        
    }
    
    
    @Override
    public boolean addChildAt(int pos, StructuralWebSocketNode child) {
        boolean result = true;
        if(pos < children.size() && children.get(pos) != null){
            result = false;
        }
        children.add(pos,child);
        //TODO add index
        return result;
    }
    
    
    @Override
    public StructuralWebSocketNode getChildAt(int i) {
        if(i < children.size() ){
            return children.get(i);
        }
        return null;
    }
    
    @Override
    public boolean removeChildAt(int pos) {
        return (children.remove(pos) != null);
    }
    
    @Override
    public boolean removeChild(StructuralWebSocketNode structuralWebSocketNode) {
        return children.remove(structuralWebSocketNode);
    }
    
    @Override
    public Iterator<StructuralWebSocketNode> getChildrenIterator() {
        return children.iterator();
    }
    
    @Override
    public WebSocketNodeType getNodeType(){
        return type;
    }
    
    /**
     * Searching for child with specific node name.
     * @param nodeName The name of the node
     * @return node if find the requested child. In any other case null
     */
    public WebSocketTreeNode findChild(String nodeName){
        for(int i = 0; i < getChildCount(); i++){
            WebSocketTreeNode child = (WebSocketTreeNode) getChildAt(i);
            if(child.getNodeName().equals(nodeName)){
                return child;
            }
        }
        return null;
    }
    
    public WebSocketTreeNode findChild(WebSocketTreeNode node){
        for(int i = 0; i < getChildCount(); i++){
            WebSocketTreeNode child = (WebSocketTreeNode) getChildAt(i);
            if (child.equals(node)){
                return child;
            }
        }
        return null;
        
    }
    
    @Override
    public boolean addParent(StructuralWebSocketNode parent){
        boolean result = true;
        if(this.parent == parent){
            return true;
        }
        if(this.parent != null && this.parent != parent){
            result = false;
            this.parent.removeChild(this);
        }
        
        this.parent = parent;
        if(parent != null){
            result = parent.addChild(this);
        }
        return result;
    }
    
    @Override
    public StructuralWebSocketNode getFirstTypeTopDown(WebSocketNodeType webSocketNodeType){
        if(this.type == webSocketNodeType){
            return this;
        }
        Iterator<StructuralWebSocketNode> iterator = getChildrenIterator();
        while (iterator.hasNext()){
            StructuralWebSocketNode child = iterator.next();
            if(child.getFirstTypeTopDown(webSocketNodeType) != null){
                return child;
            }
        }
        return null;
    }
    
    @Override
    public StructuralWebSocketNode getFirstTypeBottomUp(WebSocketNodeType webSocketNodeType){
        if(this.type == webSocketNodeType){
            return this;
        }else if (this.type == WebSocketNodeType.FOLDER_ROOT){
            return null;
        }
        return parent.getFirstTypeBottomUp(webSocketNodeType);
    }
    
    @Override
    public StructuralWebSocketNode getFirstTypeSibling(WebSocketNodeType webSocketNodeType){
        if(this.type == webSocketNodeType){
            return this;
        }
        
        Iterator<StructuralWebSocketNode> iterator = parent.getChildrenIterator();
        StructuralWebSocketNode currentNode;
        while (iterator.hasNext()){
            currentNode = iterator.next();
            if(currentNode.getNodeType() == webSocketNodeType){
                return currentNode;
            }
        }
        return null;
    }
    
    
    @Override
    public boolean equals(Object someObject) {
        boolean result = false;
        if(someObject instanceof StructuralWebSocketNode){
            StructuralWebSocketNode structuralWebSocketNode = (StructuralWebSocketNode) someObject;
            if(structuralWebSocketNode.getNodeType() == this.type) {
                if (structuralWebSocketNode instanceof WebSocketMessageNode) {
                    WebSocketMessageNode webSocketMessageNode = (WebSocketMessageNode) structuralWebSocketNode;
                    result = webSocketMessageNode.equals(this);
                } else {
                    result = this.getNodeName().equals(((StructuralWebSocketNode) someObject).getNodeName());
                }
            }
        }
        return result;
    }
    
    @Override
    public void setNodeIndex(int[] nodeIndex){
        this.nodeIndex = nodeIndex;
    }
    
    @Override
    public int[] getNodeIndex(){
        return nodeIndex;
    }
    
    public boolean hasSameNodeName(String nodeName){
        return this.nodeName.equals(nodeName);
    }
    
    @Override
    public int hashCode() {
        return super.hashCode();
    }
    
}
