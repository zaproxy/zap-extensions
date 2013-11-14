/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.plugnhack.fuzz;

import java.util.List;
import java.util.regex.Pattern;

import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.FuzzableComponent;
import org.zaproxy.zap.extension.fuzz.FuzzerContentPanel;
import org.zaproxy.zap.extension.fuzz.FuzzerHandler;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.search.SearchResult;

public class ClientMessageFuzzerHandler implements FuzzerHandler {
	
	private ClientMessageFuzzDialog dialog = null;
	private ClientMessageFuzzerContentPanel panel = new ClientMessageFuzzerContentPanel();
	private ExtensionFuzz extFuzz;
	private ExtensionPlugNHack extPnh;
	
	public ClientMessageFuzzerHandler(ExtensionFuzz extFuzz, ExtensionPlugNHack extPnh) {
		super();
		this.extFuzz = extFuzz;
		this.extPnh = extPnh;
	}

	@Override
	public void showFuzzDialog(FuzzableComponent fuzzableComponent) {
		this.getDialog(fuzzableComponent).setVisible(true);
	}

	@Override
	public FuzzerContentPanel getFuzzerContentPanel() {
		return panel;
	}

	@Override
	public List<SearchResult> searchResults(Pattern pattern, boolean inverse) {
		// TODO Implement!
		return null;
	}

	private ClientMessageFuzzDialog getDialog(FuzzableComponent fuzzableComponent) {
		if (dialog == null) {
			dialog = new ClientMessageFuzzDialog(extFuzz, extPnh, fuzzableComponent);
        } else {
        	// re-use dialog, such that the previous selection of the
        	// fuzzer & its category is not lost.
        	dialog.setFuzzableComponent(fuzzableComponent);
		}
		return dialog;
	}
}
