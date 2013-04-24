/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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

import org.mozilla.zest.core.v1.ZestElement;

public class ZestTreeElement extends ZestElement {
	
	public enum Type {TARGETED_SCRIPT, PASSIVE_SCRIPT, COMMON_TESTS};
	
	private Type type;
	
	public ZestTreeElement (Type type) {
		this.type = type;
	}

	public ZestElement deepCopy() {
		return new ZestTreeElement(this.type);
	}

	public Type getType() {
		return type;
	}

	@Override
	public boolean isSameSubclass(ZestElement ze) {
		return ze instanceof ZestTreeElement && this.type.equals(((ZestTreeElement)ze).getType());
	}
	
	public static boolean isSubclass(ZestElement ze, Type type) {
		return ze instanceof ZestTreeElement && type.equals(((ZestTreeElement)ze).getType());
	}
	
}
