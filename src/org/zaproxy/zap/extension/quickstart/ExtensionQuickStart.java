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
import java.io.BufferedWriter;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import java.util.List;
import java.util.Vector;

import org.apache.log4j.Logger;
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
	private static final Logger LOGGER = Logger.getLogger(ExtensionQuickStart.class);
	
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
		}
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

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_QUICK_URL_IDX].isEnabled()) {
        	Vector<String> params = arguments[ARG_QUICK_URL_IDX].getArguments();
            if (params.size() == 1) {
				QuickAttacker quickAttacker;
				if (View.isInitialised()) {
					quickAttacker = new UIQuickAttacker();
				} else {
					quickAttacker = new HeadlessQuickAttacker();
				}

				if (!quickAttacker.attack(params.get(0))) {
					return;
				}

	    		this.runningFromCmdLine = true;

				while (this.runningFromCmdLine) {
					// Loop until the attack thread completes
					try {
						Thread.sleep(1000);
					} catch (InterruptedException ignore) {
					}
				}

			    if (arguments[ARG_QUICK_OUT_IDX].isEnabled()) {
			    	quickAttacker.saveReport(Paths.get(arguments[ARG_QUICK_OUT_IDX].getArguments().get(0)));
                } else {
			    	quickAttacker.handleNoSavedReport();
                }
            }
        } else {
            return;
        }
    }

    private void saveReportTo(Path file) throws Exception {
        try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            writer.write(getScanReport());
        }
    }

    private String getScanReport() throws Exception {
        ReportLastScan report = new ReportLastScan();
        StringBuilder rpt = new StringBuilder();
        report.generate(rpt, getModel());
        return rpt.toString();
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_QUICK_URL_IDX] = new CommandLineArgument("-quickurl", 1, null, "", 
        		"-quickurl [target url]: " + Constant.messages.getString("quickstart.cmdline.url.help"));
        arguments[ARG_QUICK_OUT_IDX] = new CommandLineArgument("-quickout", 1, null, "", 
        		"-quickout [output filename]: " + Constant.messages.getString("quickstart.cmdline.out.help"));
        return arguments;
    }

    @Override
    public List<String> getHandledExtensions() {
    	return null;
    }

	@Override
	public boolean handleFile(File file) {
		// Not supported
		return false;
	}

	private abstract static class QuickAttacker {

		public abstract boolean attack(String url);

		protected final boolean isValid(Path file) {
			if (Files.notExists(file)) {
				if (file.getParent() == null || !Files.isWritable(file.getParent())) {
					reportError(MessageFormat.format(
							Constant.messages.getString("quickstart.cmdline.quickout.error.dirNotWritable"),
							file.getParent() == null ? file.toAbsolutePath() : file.getParent().toAbsolutePath().normalize()));
					return false;
				}
			} else if (!Files.isRegularFile(file)) {
				reportError(MessageFormat.format(
						Constant.messages.getString("quickstart.cmdline.quickout.error.notAFile"),
						file.toAbsolutePath().normalize()));
				return false;
			} else if (!Files.isWritable(file)) {
				reportError(MessageFormat.format(
						Constant.messages.getString("quickstart.cmdline.quickout.error.fileNotWritable"),
						file.toAbsolutePath().normalize()));
				return false;
			}

			return true;
		}

		protected abstract void reportError(String error);

		public abstract void saveReport(Path file);

		public abstract void handleNoSavedReport();
	}

	private class UIQuickAttacker extends QuickAttacker {

		@Override
		public boolean attack(String url) {
			getQuickStartPanel().setAttackUrl(url);
			return getQuickStartPanel().attackUrl();
		}

		@Override
		protected void reportError(String error) {
			View.getSingleton().showWarningDialog(error);
		}

		@Override
		public void saveReport(Path file) {
			if (!isValid(file)) {
				return;
			}
			try {
				saveReportTo(file);
				View.getSingleton().showMessageDialog(
						MessageFormat.format(
								Constant.messages.getString("quickstart.cmdline.quickout.save.report.successful"),
								file.toAbsolutePath().normalize()));
			} catch (Exception e) {
				reportError(Constant.messages.getString("quickstart.cmdline.quickout.error.save.report"));
				LOGGER.error("Failed to generate report: ", e);
			}
		}

		@Override
		public void handleNoSavedReport() {
			// Do nothing, the user has the UI to generate the report if (s)he wants to.
		}
	}

	private class HeadlessQuickAttacker extends QuickAttacker {

		@Override
		public boolean attack(String url) {
			URL targetURL;
			try {
				targetURL = new URL(url);
			} catch (MalformedURLException e) {
				reportError(Constant.messages.getString("quickstart.cmdline.quickurl.error.invalidUrl"));
				e.printStackTrace();
				return false;
			}

			ExtensionQuickStart.this.attack(targetURL);
			return true;
		}

		@Override
		protected void reportError(String error) {
			System.out.println(error);
		}

		@Override
		public void saveReport(Path file) {
			System.out.println(MessageFormat.format(
					Constant.messages.getString("quickstart.cmdline.outputto"),
					file.toAbsolutePath().toString()));

			if (!isValid(file)) {
				return;
			}

			try {
				saveReportTo(file);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		@Override
		public void handleNoSavedReport() {
			try {
				// Just output to stdout
				System.out.println(getScanReport());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
