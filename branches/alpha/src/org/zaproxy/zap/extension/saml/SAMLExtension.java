package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.saml.ui.SamlExtentionSettingsUI;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;

public class SAMLExtension extends ExtensionAdaptor {

    protected static final Logger log = Logger.getLogger(SAMLExtension.class);

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        try {
            SAMLConfiguration conf = SAMLConfiguration.getConfigurations();
            if(conf!=null){
                conf.initialize();
            } else {
                log.error("SAML Configuration can't be loaded. Extention will not be loaded...");
            }
            if (getView() != null && conf!=null) {
                final SAMLProxyListener proxyListener = new SAMLProxyListener();
                extensionHook.addProxyListener(proxyListener);

                ExtensionPopupMenu samlMenu = new ExtensionPopupMenu("SAML Actions");
                ExtensionPopupMenuItem samlResendMenuItem = new SAMLResendMenuItem("Resend...");

                samlMenu.add(samlResendMenuItem);
                extensionHook.getHookMenu().addPopupMenuItem(samlMenu);

                JMenuItem samlActiveEditorMenu = new JMenuItem("SAML Request Editor");
                samlActiveEditorMenu.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        SamlExtentionSettingsUI settingUI = new SamlExtentionSettingsUI(proxyListener);
                        settingUI.setVisible(true);
                    }
                });
                extensionHook.getHookMenu().addToolsMenuItem(samlActiveEditorMenu);
            }
        } catch (SAMLException e) {
            log.error("SAML Extension can't be loaded. Configuration not found or invalid");
        }
    }
}
