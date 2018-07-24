package org.zaproxy.zap.extension.websocket.treemap.nodes;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public abstract class WebSocketTreeNode implements StructuralWebSocketNode {
    
    protected WebSocketNodeType type;
    protected StructuralWebSocketNode parent;
    protected List<StructuralWebSocketNode> children;
    protected String nodeName;
    
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
    public String getNodeName() {
        return nodeName;
    }
    
    @Override
    public boolean isLeaf(){
        return children.isEmpty();
    }
    
    @Override
    public void addChild(StructuralWebSocketNode child) {
        if(!children.contains(child)){
            children.add(child);
            child.addParent(this);
        }
        
    }
    
    
    @Override
    public boolean addChildAt(int pos, StructuralWebSocketNode child) {
        boolean result = true;
        if(pos < children.size() && children.get(pos) != null){
            result = false;
        }
        children.add(pos,child);
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
    public boolean isSameAs(StructuralWebSocketNode var1) {
        if(var1.getNodeType() == type && var1.getNodeName().equals(nodeName) ){
            return true;
        }else{
            return false;
        }
    }
    
    @Override
    public boolean equals(StructuralWebSocketNode var1){
        if(!isSameAs(var1) || !parent.isSameAs(var1.getParent()) || !this.children.equals(var1.getChildren()) ){
            return false;
        }
        return true;
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
    
    
    @Override
    public boolean addParent(StructuralWebSocketNode parent){
        boolean result = true;
        if(this.parent != null && this.parent != parent){
            result = false;
            this.parent.removeChild(this);
        }else{
            this.parent = parent;
            if(parent != null){
                parent.addChild(this);
            }
        }
        return result;
    }
    
    @Override
    public StructuralWebSocketNode getFirstTypeTopDown(WebSocketNodeType webSocketNodeType){
        if(this.type == webSocketNodeType){
            return this;
        }else if (this.type == WebSocketNodeType.HANDSHAKE){
            return parent.getFirstTypeBottomUp(webSocketNodeType);
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
    public boolean equals(Object someObject) {
        if(someObject instanceof StructuralWebSocketNode){
            return this.getNodeName().equals(((StructuralWebSocketNode) someObject).getNodeName());
        }
        return false;
    }
    
    public boolean hasSameNodeName(String nodeName){
        return this.nodeName.equals(nodeName);
    }
}
