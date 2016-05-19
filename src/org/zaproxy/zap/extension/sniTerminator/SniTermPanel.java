/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 mawoki@ymail.com
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
package org.zaproxy.zap.extension.sniTerminator;

import java.awt.GridBagLayout;

import javax.swing.JLabel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

public class SniTermPanel extends AbstractParamPanel {

	private static final long serialVersionUID = 1L;
	
	private ExtensionSniTerminator extension;

    private ZapTextField txtProxyIp = null;
    private ZapPortNumberSpinner spinnerProxyPort = null;

	/**
	 * Create the panel.
	 */
	public SniTermPanel(ExtensionSniTerminator extension) {
		super();
		this.extension = extension;

		setName(Constant.messages.getString(ExtensionSniTerminator.PREFIX + ".options.name"));

        this.setLayout(new GridBagLayout());

        JLabel serverLabel = new JLabel(Constant.messages.getString(ExtensionSniTerminator.PREFIX + ".options.server"));
        serverLabel.setLabelFor(this.getTxtProxyIp());
        this.add(serverLabel, LayoutHelper.getGBC(0, 1, 1, 0.6));
        this.add(this.getTxtProxyIp(), LayoutHelper.getGBC(1, 1, 1, 0.4));

        JLabel portLabel = new JLabel(Constant.messages.getString(ExtensionSniTerminator.PREFIX + ".options.port"));
        portLabel.setLabelFor(this.getSpinnerProxyPort());
        this.add(portLabel, LayoutHelper.getGBC(0, 2, 1, 0.6));
        this.add(this.getSpinnerProxyPort(), LayoutHelper.getGBC(1, 2, 1, 0.4));

        // Spacer
        this.add(new JLabel(), LayoutHelper.getGBC(1, 3, 2, 1.0, 1.0));

	}

    private ZapTextField getTxtProxyIp() {
        if (txtProxyIp == null) {
            txtProxyIp = new ZapTextField("");
        }
        return txtProxyIp;
    }

    private ZapPortNumberSpinner getSpinnerProxyPort() {
        if (spinnerProxyPort == null) {
            // ZAP: Do not allow invalid port numbers
            spinnerProxyPort = new ZapPortNumberSpinner(8080);
        }
        return spinnerProxyPort;
    }

	@Override
	public void initParam(Object obj) {
		final OptionsParam options = (OptionsParam) obj;
		final SniTermParam param = options.getParamSet(SniTermParam.class);
		this.getTxtProxyIp().setText(param.getServerAddress());
		this.getSpinnerProxyPort().setValue(param.getServerPort());
	}

	@Override
	public void validateParam(Object obj) throws Exception {
		// nothing to do here ...
	}

	@Override
	public void saveParam(Object obj) throws Exception {
		final OptionsParam options = (OptionsParam) obj;
		final SniTermParam param = options.getParamSet(SniTermParam.class);
		boolean changed = false;
		if (!param.getServerAddress().equals(this.getTxtProxyIp().getText())) {
			param.setServerAddress(this.getTxtProxyIp().getText());
			changed = true;
		}
		if (param.getServerPort() != this.getSpinnerProxyPort().getValue()) {
			param.setServerPort(this.getSpinnerProxyPort().getValue());
			changed = true;
		}
		if (changed) {
			this.extension.initSniTerminator();
		}
	}
	
	@Override
	public String getHelpIndex() {
		return null;
	}

}

