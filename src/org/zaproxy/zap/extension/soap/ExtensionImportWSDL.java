/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright The ZAP development team
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
package org.zaproxy.zap.extension.soap;

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.JFileChooser;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportWSDL extends ExtensionAdaptor {

	public static final String NAME = "ExtensionImportWSDL";

	private static final String THREAD_PREFIX = "ZAP-Import-WSDL-";

    private ZapMenuItem menuImportLocalWSDL = null;
    private ZapMenuItem menuImportUrlWSDL = null;
    private int threadId = 1;

	private static final Logger log = Logger.getLogger(ExtensionImportWSDL.class);
	private WSDLCustomParser parser = new WSDLCustomParser();
	
	public ExtensionImportWSDL() {
		super(NAME);
		this.setOrder(158);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

	    if (getView() != null) {
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuImportLocalWSDL());
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuImportUrlWSDL());
	        
			/* Custom spider is added in order to explore not only WSDL files, but also their WSDL endpoints. */
	        WSDLSpider.enable();
			ExtensionSpider spider = (ExtensionSpider) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.NAME);
			SpiderParser customSpider = new WSDLSpider();
			if (spider != null){
				spider.addCustomParser(customSpider);
				log.info("Added custom WSDL spider.");
			}else{
				log.info("Custom WSDL spider could not be added.");
			}
	    }
	}

	@Override
	public void unload() {
		super.unload();
		/* Disables menu options. */
		Control control = Control.getSingleton();
		ExtensionLoader extLoader = control.getExtensionLoader();
	    if (getView() != null) {
	    	extLoader.removeToolsMenuItem(getMenuImportLocalWSDL());
	    	extLoader.removeToolsMenuItem(getMenuImportUrlWSDL());
	    }
	    /* Destroys current ImportWSDL singleton instance. */
	    ImportWSDL.destroy();
	    /* Disables custom spider. */
		WSDLSpider.disable();
	}

	/* Menu option to import a local WSDL file. */
	private ZapMenuItem getMenuImportLocalWSDL() {
        if (menuImportLocalWSDL == null) {
        	menuImportLocalWSDL = new ZapMenuItem("soap.topmenu.tools.importWSDL",
        			KeyStroke.getKeyStroke(KeyEvent.VK_I, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask(), false));
        	menuImportLocalWSDL.setToolTipText(Constant.messages.getString("soap.topmenu.tools.importWSDL.tooltip"));

        	menuImportLocalWSDL.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	// Prompt for a WSDL file.
            		final JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            		FileNameExtensionFilter filter = new FileNameExtensionFilter("WSDL File", "wsdl", "wsdl");
            		chooser.setFileFilter(filter);
            	    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
            	    if(rc == JFileChooser.APPROVE_OPTION) {
            	    	parser.extFileWSDLImport(chooser.getSelectedFile(), THREAD_PREFIX + threadId++);
            	    }

                }
            });
        }
        return menuImportLocalWSDL;
    }
	
	/* Menu option to import a WSDL file from a given URL. */
	private ZapMenuItem getMenuImportUrlWSDL() {
        if (menuImportUrlWSDL == null) {
        	menuImportUrlWSDL = new ZapMenuItem("soap.topmenu.tools.importRemoteWSDL",
        			KeyStroke.getKeyStroke(KeyEvent.VK_J, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask(), false));
        	menuImportUrlWSDL.setToolTipText(Constant.messages.getString("soap.topmenu.tools.importRemoteWSDL.tooltip"));

        	final ExtensionImportWSDL shadowCopy = this;
        	menuImportUrlWSDL.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            new ImportFromUrlDialog(View.getSingleton().getMainFrame(), shadowCopy);
                        }
                    });
                }
            });
        }
        return menuImportUrlWSDL;
    }
	
	/* Called from external classes in a threaded mode. */
	public void extUrlWSDLImport(final String url){
		parser.extUrlWSDLImport(url, THREAD_PREFIX + threadId++);
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("soap.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
}
