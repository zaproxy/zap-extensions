package org.zaproxy.zap.extension.websocket.treemap;

import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketFolderNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


public class WebSocketTreeNodeUnitTest extends WebSocketTestUtils {
    
    @Before
    public void openWebSocketServer() throws Exception {
        super.setUpZap();
    }
    
    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }
    
    @Test
    public void shouldAddChildren(){
        WebSocketFolderNode rootFolder = WebSocketFolderNode.getRootFolderNode();
        
        WebSocketFolderNode childOfRoot = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES,"child_of_root",rootFolder);
        
        WebSocketFolderNode child_1_OfChildOfRoot = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_1_of_child_of_root",null);
        childOfRoot.addChild(child_1_OfChildOfRoot);
        
        WebSocketFolderNode child_2_OfChildOfRoot = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_2_of_child_of_root",null);
        child_2_OfChildOfRoot.addParent(childOfRoot);
        
        //Checks root folder. Add in children list from child's constructure
        assertThat(rootFolder.getChildCount(),is(1));
        assertThat(rootFolder.getChildAt(0), is(childOfRoot));
        
        //Checks if Add parent at constructure and child at addChild method
        assertThat(childOfRoot.getParent(),is(rootFolder));
        assertThat(childOfRoot.getChildAt(0),is(child_1_OfChildOfRoot));
        
        //Checks if add child in addChild method
        assertThat(child_1_OfChildOfRoot.getParent(),is(childOfRoot));
        assertNull(child_1_OfChildOfRoot.getChildAt(0));
        
        //Check if add parent in addParent method
        assertThat(child_2_OfChildOfRoot.getParent(),is(childOfRoot));
        assertThat(childOfRoot.getChildAt(1),is(child_2_OfChildOfRoot));
    
    }
    
    @Test
    public void testIRemoveChild(){
        WebSocketTreeNode rootFolder_1 = WebSocketFolderNode.getRootFolderNode();
        WebSocketTreeNode rootFolder_2 = WebSocketFolderNode.getRootFolderNode();
        
        WebSocketTreeNode childOfRoot_1 = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_of_root_1",rootFolder_1);
        new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_of_root_2",rootFolder_2);
        WebSocketTreeNode child_2_OfRoot_2 = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_2_of_root_2",rootFolder_2);
        
        assertTrue(rootFolder_1.removeChild(childOfRoot_1));
        assertFalse(rootFolder_1.removeChild(childOfRoot_1));
        
        assertTrue(rootFolder_2.removeChildAt(1));
        assertFalse(rootFolder_1.removeChild(child_2_OfRoot_2));
        assertTrue(rootFolder_2.removeChildAt(0));
        assertEquals(rootFolder_1.getChildCount(),0);
        assertEquals(rootFolder_2.getChildCount(),0);
    }
    
    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldIndexOutOfBoundExceptionInRemoveChild(){
        WebSocketFolderNode rootFolder = new WebSocketFolderNode(WebSocketNodeType.FOLDER_ROOT,"root",null);
        rootFolder.removeChildAt(1);
    }
    
    @Test
    public void shouldAddGetChildAt(){
        WebSocketFolderNode rootFolder = new WebSocketFolderNode(WebSocketNodeType.FOLDER_ROOT,"root",null);
        WebSocketFolderNode childOfRootAt_0_1 = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES,"child_of_root",null);
        WebSocketFolderNode childOfRootAt_0_0 = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_of_root_2",null);
        
        assertTrue(rootFolder.addChildAt(0,childOfRootAt_0_1));
        assertThat(rootFolder.getChildAt(0),is(childOfRootAt_0_1));
        
        assertFalse(rootFolder.addChildAt(0,childOfRootAt_0_0));
        assertThat(rootFolder.getChildAt(0),is(childOfRootAt_0_0));
        assertThat(rootFolder.getChildAt(1),is(childOfRootAt_0_1));
    }
    
    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldIndexOutOfBoundExceptionInAddChildAt(){
        WebSocketFolderNode rootFolder = new WebSocketFolderNode(WebSocketNodeType.FOLDER_ROOT,"root",null);
        WebSocketFolderNode childOutOfBound = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS,"child_2_of_child_of_root",null);
        int index = rootFolder .getChildCount() + 1;
        rootFolder.addChildAt(index, childOutOfBound);
    }
    
    
    @Test
    public void shouldBeOrNotBeLeaf(){
        WebSocketFolderNode rootFolder = WebSocketFolderNode.getRootFolderNode();
        WebSocketFolderNode childOfRoot = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES,"child_of_root",rootFolder);
        
        assertFalse(rootFolder.isLeaf());
        assertTrue(childOfRoot.isLeaf());
        
        WebSocketTreeNode childOfChildOfRoot = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES,"child_of_child_of_root",childOfRoot);
        assertFalse(childOfRoot.isLeaf());
        assertTrue(childOfChildOfRoot.isLeaf());
        
    }
    
}
