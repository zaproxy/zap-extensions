/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 ZAP development team
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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.apache.commons.httpclient.Cookie;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestVariables;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestRequestDialog extends StandardFieldsDialog implements ZestDialog {

	private static final String FIELD_URL = "zest.dialog.request.label.url"; 
	private static final String FIELD_METHOD = "zest.dialog.request.label.method"; 
	private static final String FIELD_HEADERS = "zest.dialog.request.label.headers"; 
	private static final String FIELD_BODY = "zest.dialog.request.label.body"; 
	private static final String FIELD_FOLLOW_REDIR = "zest.dialog.request.label.followredir";

	private static final String FIELD_RESP_STATUS_CODE = "zest.dialog.request.label.respstatus"; 
	private static final String FIELD_RESP_TIME_MS = "zest.dialog.request.label.resptime"; 
	private static final String FIELD_RESP_HEADERS = "zest.dialog.request.label.respheaders"; 
	private static final String FIELD_RESP_BODY = "zest.dialog.request.label.respbody";

	private static final long serialVersionUID = 1L;

	private ExtensionZest extension = null;
	private ScriptNode parent = null;
	private ScriptNode node = null;
	private boolean add = false;
	
	private ZestRequest request = null;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable cookiesTable = null;
    private CookiesTableModel cookiesModel = null;
    private ZestCookieDialog cookieDialog = null;

	public ZestRequestDialog(ExtensionZest ext, Frame owner, Dimension dim) {
		super(owner, "zest.dialog.request.title", dim,
			new String[] {
                "zest.dialog.request.tab.main",
                "zest.dialog.request.tab.cookies",
                "zest.dialog.request.tab.response"});

		this.extension = ext;
	}

	public void init (ScriptNode parent, ScriptNode node) {
		this.parent = parent;
		if (node == null) {
			this.node = new ScriptNode();
			request = new ZestRequest();
			this.node.setUserObject(request);
			add = true;
		} else {
			this.node = node;
			this.request = (ZestRequest) ZestZapUtils.getElement(node);
			add = false;
		}
		
		this.removeAllFields();
		this.getCookieModel().clear();
		for (Cookie cookie : this.request.getCookies()) {
			this.getCookieModel().add(cookie.getDomain(), cookie.getName(), cookie.getValue(), cookie.getPath());
		}
		
		// Request tab
		this.addNodeSelectField(0, FIELD_URL, null, true, false);
		if (request.getUrl() != null) {
			this.setFieldValue(FIELD_URL, request.getUrl().toString());
		} else {
			this.setFieldValue(FIELD_URL, request.getUrlToken());
		}
		this.addComboField(0, FIELD_METHOD, new String[] {"GET", "POST", "{{" + ZestVariables.REQUEST_METHOD + "}}"}, request.getMethod());
		this.addCheckBoxField(0, FIELD_FOLLOW_REDIR, request.isFollowRedirects());
		this.addMultilineField(0, FIELD_HEADERS, request.getHeaders());
		this.addMultilineField(0, FIELD_BODY, request.getData());
		
		// Enable right click menus
		this.addFieldListener(FIELD_URL, ZestZapUtils.stdMenuAdapter()); 
		this.addFieldListener(FIELD_HEADERS, ZestZapUtils.stdMenuAdapter()); 
		this.addFieldListener(FIELD_BODY, ZestZapUtils.stdMenuAdapter()); 

		// Cookies tab
        List<JButton> buttons = new ArrayList<JButton>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());
        
        this.addTableField(1, this.getCookiesTable(), buttons);

		// Response tab
		if (request.getResponse() != null) {
			this.addComboField(2, FIELD_RESP_STATUS_CODE, statusCodeStrings(), 
					Integer.toString(request.getResponse().getStatusCode()), false);
			this.addNumberField(2, FIELD_RESP_TIME_MS, 0, Integer.MAX_VALUE, (int)request.getResponse().getResponseTimeInMs());
			this.addMultilineField(2, FIELD_RESP_HEADERS, request.getResponse().getHeaders());
			this.addMultilineField(2, FIELD_RESP_BODY, request.getResponse().getBody());
		} else {
			this.addComboField(2, FIELD_RESP_STATUS_CODE, statusCodeStrings(), 
					Integer.toString(HttpStatusCode.OK), false);
			this.addNumberField(2, FIELD_RESP_TIME_MS, 0, Integer.MAX_VALUE, 0);
			this.addMultilineField(2, FIELD_RESP_HEADERS, "");
			this.addMultilineField(2, FIELD_RESP_BODY, "");
		}
	}
	
	private String[] statusCodeStrings() {
		String [] strArray = new String[HttpStatusCode.CODES.length];
		for (int i=0; i < HttpStatusCode.CODES.length; i++) {
			strArray[i] = Integer.toString(HttpStatusCode.CODES[i]);
		}
		return strArray;
	}

	@Override
	public void siteNodeSelected(String field, SiteNode node) {
		if (node != null) {
			this.setFieldValue(FIELD_METHOD, node.getHistoryReference().getMethod());
		}
	}

	public void save() {
		try {
			this.request.setUrl(new URL(this.getStringValue(FIELD_URL)));
		} catch (MalformedURLException e) {
			// Assume this is because it includes a token
			this.request.setUrlToken(this.getStringValue(FIELD_URL));
		}
		this.request.setMethod(this.getStringValue(FIELD_METHOD));
		this.request.setHeaders(this.getStringValue(FIELD_HEADERS));
		this.request.setFollowRedirects(this.getBoolValue(FIELD_FOLLOW_REDIR));
		this.request.setData(this.getStringValue(FIELD_BODY));
		
		// handle cookies
		this.request.clearCookies();
		for (String[] cookie : this.cookiesModel.getValues()) {
			// todo expire and secure ok to default??
			this.request.addCookie(cookie[0], cookie[1], cookie[2], cookie[3], null, false);
		}
		
		if (this.request.getResponse() != null) {
			this.request.getResponse().setHeaders(this.getStringValue(FIELD_RESP_HEADERS));
			this.request.getResponse().setBody(this.getStringValue(FIELD_RESP_BODY));
		} else if (! this.isEmptyField(FIELD_RESP_HEADERS) && ! this.isEmptyField(FIELD_RESP_BODY)) {
			this.request.setResponse(
							new ZestResponse(this.request.getUrl(), 
									this.getStringValue(FIELD_RESP_HEADERS), 
									this.getStringValue(FIELD_RESP_BODY), 
									Integer.parseInt(this.getStringValue(FIELD_RESP_STATUS_CODE)), 
									this.getIntValue(FIELD_RESP_TIME_MS)));
		}
		
		if (add) {
			this.extension.addToParent(this.parent, this.request);
		} else {
			this.extension.updated(node);
			this.extension.display(node, false);
		}

	}

    private JButton getAddButton () {
    	if (this.addButton == null) {
    		this.addButton = new JButton(Constant.messages.getString("zest.dialog.script.button.add"));
    		this.addButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					ZestCookieDialog dialog = getCookieDialog();
					if (! dialog.isVisible()) {
						// Try to set up a sensible default domain
						String domain = "";
						URL url = request.getUrl();
						if (url == null) {
							// Happens on a new request dialog
							try {
								url = new URL(getStringValue(FIELD_URL));
							} catch (MalformedURLException e2) {
								// Ignore - it could not be set up or parameterized
							}
						}
						if (url != null) {
							if (url.getPort() > 0) {
								domain = url.getHost() + ":" + url.getPort();
							} else {
								domain = url.getHost();
							}
						}
						dialog.init(getScript(), domain, "", "", "/", true, -1, true);
						dialog.setVisible(true);
					}
				}});
    	}
    	return this.addButton;
    }
    
    private JButton getModifyButton () {
    	if (this.modifyButton == null) {
    		this.modifyButton = new JButton(Constant.messages.getString("zest.dialog.script.button.modify"));
    		this.modifyButton.setEnabled(false);
    		this.modifyButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					ZestCookieDialog dialog = getCookieDialog();
					if (! dialog.isVisible()) {
						int row = getCookiesTable().getSelectedRow();
						dialog.init(
								getScript(),
								(String)getCookieModel().getValueAt(row, 0), 
								(String)getCookieModel().getValueAt(row, 1), 
								(String)getCookieModel().getValueAt(row, 2), 
								(String)getCookieModel().getValueAt(row, 3), 
								false, row, true);
						dialog.setVisible(true);
					}
				}});
    	}
    	return this.modifyButton;
    }
    
    private JButton getRemoveButton () {
    	if (this.removeButton == null) {
    		this.removeButton = new JButton(Constant.messages.getString("zest.dialog.script.button.remove"));
    		this.removeButton.setEnabled(false);
    		final ZestRequestDialog parent = this;
    		this.removeButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					if (JOptionPane.OK_OPTION == 
							View.getSingleton().showConfirmDialog(parent, 
									Constant.messages.getString("zest.dialog.script.remove.confirm"))) {
						getCookieModel().remove(getCookiesTable().getSelectedRow());
					}
				}});
    	}
    	return this.removeButton;
    }
    
    private ZestCookieDialog getCookieDialog() {
    	if (this.cookieDialog == null) {
    		this.cookieDialog = new ZestCookieDialog(this.getCookieModel(), this, new Dimension(300, 200)); 
    	}
    	return this.cookieDialog;
    }

    private JTable getCookiesTable() {
    	if (cookiesTable == null) {
    		cookiesTable = new JTable();
    		cookiesTable.setModel(getCookieModel());
    		cookiesTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
				@Override
				public void valueChanged(ListSelectionEvent e) {
					if (getCookiesTable().getSelectedRowCount() == 0) {
			    		modifyButton.setEnabled(false);
			    		removeButton.setEnabled(false);
					} else if (getCookiesTable().getSelectedRowCount() == 1) {
			    		modifyButton.setEnabled(true);
			    		removeButton.setEnabled(true);
					} else {
			    		modifyButton.setEnabled(false);
			    		// TODO allow multiple deletions?
			    		removeButton.setEnabled(false);
					}
				}});
    	}
    	return cookiesTable;
    }

    private CookiesTableModel getCookieModel() {
        if (cookiesModel == null) {
            cookiesModel = new CookiesTableModel();
        }
        return cookiesModel;
    }

	@Override
	public String validateFields() {
		// TODO is there any validation we can do now? The below doesnt work with tokens...
		/* 
		try {
			new URL(this.getStringValue(FIELD_URL));
		} catch (MalformedURLException e) {
			return Constant.messages.getString("zest.dialog.request.error.url");
		}
		*/
		return null;
	}

	@Override
	public ZestScriptWrapper getScript() {
		return extension.getZestTreeModel().getScriptWrapper(node);
	}
	
}
