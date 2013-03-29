/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.zest;

import javax.swing.tree.DefaultMutableTreeNode;

import org.mozilla.zest.core.v1.ZestElement;
import org.parosproxy.paros.Constant;

/**
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class ZestNode extends DefaultMutableTreeNode {
	private static final long serialVersionUID = 1L;
	private String nodeName = null;
	private boolean shadow = false;
    
	public ZestNode() {
		// Only use for the root node
        super();
        this.nodeName = Constant.messages.getString("zest.tree.root");
    }

	public ZestNode(ZestElement element) {
		this(element, false);
	}

	public ZestNode(ZestElement element, boolean shadow) {
        super();
        this.shadow = shadow;
        this.nodeName = ZestZapUtils.toUiString(element, true, this.shadow);
        this.setUserObject(element);
    }
    
    @Override
    public String toString() {
        return nodeName;
    }

	public String getNodeName() {
		return nodeName;
	}
	
	public void nameChanged() {
        this.nodeName = ZestZapUtils.toUiString((ZestElement)this.getUserObject(), true, this.shadow);
	}
	
	public ZestElement getZestElement() {
		return (ZestElement) this.getUserObject();
	}
	
	@Override
	public ZestNode getParent() {
		return (ZestNode) super.getParent();
	}

	public boolean isShadow() {
		return shadow;
	}

	public void setShadow(boolean shadow) {
		this.shadow = shadow;
	}
	
}
