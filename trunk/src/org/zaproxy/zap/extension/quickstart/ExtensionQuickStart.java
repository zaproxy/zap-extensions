/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
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
package org.zaproxy.zap.extension.quickstart;

import java.awt.Container;
import java.io.File;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.List;
import java.util.Vector;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.report.ReportLastScan;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ext.ExtensionExtension;
import org.zaproxy.zap.extension.help.ExtensionHelp;

public class ExtensionQuickStart extends ExtensionAdaptor implements SessionChangedListener, CommandLineListener {
	
	public static final String NAME = "ExtensionQuickStart";
	protected static final String SCRIPT_CONSOLE_HOME_PAGE = Constant.ZAP_HOMEPAGE;
	
	private QuickStartPanel quickStartPanel = null;
	private AttackThread attackThread = null;
	
	private CommandLineArgument[] arguments = new CommandLineArgument[2];
    private static final int ARG_QUICK_URL_IDX = 0;
    private static final int ARG_QUICK_OUT_IDX = 1;
    
    private boolean runningFromCmdLine = false;

    public ExtensionQuickStart() {
        super();
 		initialize();
    }

    /**
     * @param name
     */
    public ExtensionQuickStart(String name) {
        super(name);
    }

	/**
	 * This method initializes this
	 */
	private void initialize() {
        this.setName(NAME);
        //this.setOrder(0);
	}
	
	@Override
	public void hook(ExtensionHook extensionHook) {
	    super.hook(extensionHook);

	    if (getView() != null) {
	        extensionHook.getHookView().addWorkPanel(getQuickStartPanel());
	        
	        ExtensionHelp.enableHelpKey(getQuickStartPanel(), "quickstart");
	    }
        extensionHook.addSessionListener(this);

	    extensionHook.addCommandLine(getCommandLineArguments());
	}

	@Override
	public boolean canUnload() {
    	return true;
    }

	private QuickStartPanel getQuickStartPanel() {
		if (quickStartPanel == null) {
			quickStartPanel = new QuickStartPanel(this);
		    quickStartPanel.setName(Constant.messages.getString("quickstart.panel.title"));
		    // Force it to be the first one
			quickStartPanel.setTabIndex(0);
		}
		return quickStartPanel;
	}
	

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("quickstart.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	public void attack (URL url) {
		if (attackThread != null && attackThread.isAlive()) {
			return;
		}
		attackThread = new AttackThread(this);
		attackThread.setURL(url);
		attackThread.start();

	}
	
	public void notifyProgress(AttackThread.Progress progress) {
		if (View.isInitialised()) {
			this.getQuickStartPanel().notifyProgress(progress);
		} else {
        	switch (progress) {
        	case notstarted:
        	case spider:
        	case ascan:
        		this.runningFromCmdLine = true;
        		break;
        	case failed:
        	case complete:
        	case stopped:
        		this.runningFromCmdLine = false;
        		break;
        	}
		}
	}

	public void stopAttack() {
		if (attackThread != null) {
			attackThread.stopAttack();
		}
	}

	public void showOnStart(boolean showOnStart) {
		if (!showOnStart) {
			// Remove the tab right away
			Container parent = this.getQuickStartPanel().getParent();
			parent.remove(this.getQuickStartPanel());
		}
		
		// Save in configs
		ExtensionExtension extExt = 
				(ExtensionExtension) Control.getSingleton().getExtensionLoader().getExtension(ExtensionExtension.NAME);
		if (extExt != null) {
			extExt.enableExtension(NAME, showOnStart);
		}
		
	}

	@Override
	public void sessionAboutToChange(Session arg0) {
		// Ignore
	}

	@Override
	public void sessionChanged(Session arg0) {
		// Ignore
	}

	@Override
	public void sessionModeChanged(Mode mode) {
		this.getQuickStartPanel().setMode(mode);
	}

	@Override
	public void sessionScopeChanged(Session arg0) {
		// Ignore
	}

    //@Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_QUICK_URL_IDX].isEnabled()) {
        	Vector<String> params = arguments[ARG_QUICK_URL_IDX].getArguments();
            if (params.size() == 1) {
            	try {
					this.attack(new URL(params.get(0)));
	        		this.runningFromCmdLine = true;

					while (this.runningFromCmdLine) {
						// Loop until the attack thread completes
						Thread.sleep(1000);
					}
				    ReportLastScan report = new ReportLastScan();
				    StringBuilder rpt = new StringBuilder();
					report.generate(rpt , getModel());
					
			        if (arguments[ARG_QUICK_OUT_IDX].isEnabled()) {
			        	File f = new File(arguments[ARG_QUICK_OUT_IDX].getArguments().get(0));
			        	System.out.println(MessageFormat.format(
			        			Constant.messages.getString("quickstart.cmdline.outputto"), f.getAbsolutePath()));
			        	PrintWriter writer = new PrintWriter(f);
			        	writer.write(rpt.toString());
			        	writer.close();
			        } else {
			        	// Just output to stdout
			        	System.out.println(rpt.toString());
			        }
					
				} catch (Exception e) {
					// Stacktrace as good an anything else right now
					e.printStackTrace();
				}
            }
        } else {
            return;
        }
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_QUICK_URL_IDX] = new CommandLineArgument("-quickurl", 1, null, "", 
        		"-quickurl [target url]: " + Constant.messages.getString("quickstart.cmdline.url.help"));
        arguments[ARG_QUICK_OUT_IDX] = new CommandLineArgument("-quickout", 1, null, "", 
        		"-quickout [output filename]: " + Constant.messages.getString("quickstart.cmdline.out.help"));
        return arguments;
    }

    public List<String> getHandledExtensions() {
    	return null;
    }

}
