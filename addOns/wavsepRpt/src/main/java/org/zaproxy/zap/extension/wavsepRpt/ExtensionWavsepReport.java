/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.wavsepRpt;

import java.awt.CardLayout;
import java.io.File;
import java.io.PrintWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * An example ZAP extension which adds a top level menu item.
 *
 * This class is defines the extension.
 */
public class ExtensionWavsepReport extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionWavsepReport";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "wavsepRpt";

    private static final String RESOURCE = "/org/zaproxy/zap/extension/wavsepRpt/resources";

    private static final ImageIcon ICON =
            new ImageIcon(ExtensionWavsepReport.class.getResource(RESOURCE + "/cake.png"));

    private static final String EXAMPLE_FILE = "example/ExampleFile.txt";

    // TODO moce all this data into files that can be (re)read before the report is run
    private static final String[][] SHORT_FORMS = {
        {"Application Error disclosure", "AppErr"},
        {"Cross Site Scripting (Reflected)", "RXSS"},
        {"Absence of Anti-CSRF Tokens", "NoCSRF"},
        {"Anti CSRF tokens scanner", "ACSRF"},
        {"Cookie set without HttpOnly flag", "HttpOnly"},
        {"Cross Site Request Forgery", "CSRF"},
        {"Content-Type header missing", "NoCTHeader"},
        {"External redirect", "ExtRedir"},
        {"HTTP Parameter Override", "ParamOver"},
        {"Information disclosure - database error messages", "InfoDb"},
        {"Information disclosure - debug error messages", "InfoDebug"},
        {"Information disclosure - sensitive informations in URL", "InfoUrl"},
        {"None. Warning only.", "NoCSRF2"},
        {"Password Autocomplete in browser", "Auto"},
        {"Path Traversal", "PathTrav"},
        {"Remote File Inclusion", "RFI"},
        {"Session ID in URL rewrite", "SessIdUrl"},
        {"SQL Injection", "SQLi"},
        {"SQL Injection - MySQL", "SqlMySql"},
        {"SQL Injection - Generic SQL RDBMS", "SqlGen"},
        {"SQL Injection - Boolean Based", "SqlBool"},
        {"SQL Injection - Error Based - Generic SQL RDBMS", "SqlGenE"},
        {"SQL Injection - Error Based - MySQL", "SqlMySqlE"},
        {"SQL Injection - Error Based - Java", "SqlJavaE"},
        {"SQL Injection (Hypersonic SQL) - Time Based", "SqlHyperT"},
        {"SQL Injection (MySQL) - Time Based", "SqlMySqTl"},
        {"SQL Injection (Oracle) - Time Based", "SqlOracleT"},
        {"SQL Injection (PostgreSQL) - Time Based", "SqlPostgreT"},
        {"URL Redirector Abuse", "UrlRedir"},
        {"Viewstate without MAC signature (Unsure)", "ViewstateNoMac"},
        {"Weak Authentication Method", "WeakAuth"},
        {"Web Browser XSS Protection Not Enabled", "XSSNoProt"},
        {"X-Content-Type-Options header missing", "XContent"},
        {"X-Frame-Options header not set", "XFrame"}
    };

    private static final String IGNORE = "ignore";
    private static final String PASS = "pass";
    private static final String FAIL = "fail";

    private static final String[][] RULES = {
        {"-", "InfoDebug", IGNORE},
        {"-", "InfoUrl", IGNORE},
        {"-", "ACSRF", IGNORE},
        {"-", "AppErr", IGNORE},
        {"-", "ExtRedir", IGNORE},
        {"-", "NoCSRF", IGNORE},
        {"-", "NoCSRF2", IGNORE},
        {"-", "NoCTHeader", IGNORE},
        {"-", "ParamOver", IGNORE},
        {"-", "XFrame", IGNORE},
        {"-", "XContent", IGNORE},
        {"-", "XSSNoProt", IGNORE},
        {"LFI-", "RXSS", IGNORE},
        {"RFI-", "RXSS", IGNORE},
        {"SInjection-", "RXSS", IGNORE},
        {"Unvalidated-Redirect", "RXSS", IGNORE},
        {"LoginBypass", "Auto", IGNORE},
        {"CrlfRemovalInHttpHeader", "HttpOnly", IGNORE},
        {"Tag2HtmlPageScopeValidViewstateRequired", "ViewstateNoMac", IGNORE},
        {"LFI-Detection-Evaluation", "PathTrav", PASS},
        {"LFI-FalsePositives", "PathTrav", FAIL},
        {"RFI-Detection-Evaluation", "RFI", PASS},
        {"RFI-FalsePositives", "RFI", FAIL},
        {"RXSS-Detection-Evaluation", "RXSS", PASS},
        {"RXSS-FalsePositives-GET", "RXSS", FAIL},
        {"Redirect-Detection", "ExtRedir", "PASS"},
        {"SInjection-Detection-Evaluation", "SQLfp", PASS},
        {"SInjection-Detection-Evaluation", "SQLi", PASS},
        // {"SInjection-Detection-Evaluation", "SqlHyper", PASS},
        {"SInjection-Detection-Evaluation", "SqlBool", PASS},
        {"SInjection-Detection-Evaluation", "SqlGen", PASS},
        {"SInjection-Detection-Evaluation", "SqlGenE", PASS},
        {"SInjection-Detection-Evaluation", "SqlMySql", PASS},
        {"SInjection-Detection-Evaluation", "SqlMySqlE", PASS},
        // {"SInjection-Detection-Evaluation", "SqlOracle", PASS},
        // {"SInjection-Detection-Evaluation", "SqlPostgre", PASS},
        {"SInjection-FalsePositives", "SQLfp", FAIL},
        {"SInjection-FalsePositives", "SQLi", FAIL},
        {"SInjection-FalsePositives", "SqlBool", FAIL},
        {"SInjection-FalsePositives", "SqlGen", FAIL},
        {"SInjection-FalsePositives", "SqlGenE", FAIL},
        {"SInjection-FalsePositives", "SqlMySql", FAIL},
        {"SInjection-FalsePositives", "SqlMySqlE", FAIL},
        {"SInjection-FalsePositives", "SqlHyper", FAIL},
        {"SInjection-FalsePositives", "SqlMySql", FAIL},
        {"SInjection-FalsePositives", "SqlOracle", FAIL},
        {"SInjection-FalsePositives", "SqlPostgre", FAIL},
        {"info-cookie-no-httponly", "HttpOnly", PASS},
        {"session-password-autocomplete", "Auto", PASS},
        {"weak-authentication-basic", "WeakAuth", PASS}
    };

    private ZapMenuItem runReportMenu = null;
    private AbstractPanel statusPanel = null;
    private ZapTextArea outputPane = null;

    private String wavsepNodeName = "wavsep";

    private Logger log = Logger.getLogger(this.getClass());

    private Set<String> missingShortForms = new HashSet<String>();

    private List<String> summaryHtmlList = new ArrayList<String>();
    private StringBuilder detailHtml = new StringBuilder();

    /** */
    public ExtensionWavsepReport() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list
            extensionHook.getHookMenu().addReportMenuItem(getRunReportMenu());
            // Register a
            extensionHook.getHookView().addStatusPanel(getStatusPanel());
        }
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(ICON);
            JScrollPane scroll = new JScrollPane();
            scroll.setViewportView(this.getOutputPane());
            statusPanel.add(scroll);
        }
        return statusPanel;
    }

    private ZapTextArea getOutputPane() {
        if (outputPane == null) {
            outputPane = new ZapTextArea();
            outputPane.setEditable(false);
            outputPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
        }
        return outputPane;
    }

    private ZapMenuItem getRunReportMenu() {
        if (runReportMenu == null) {
            runReportMenu = new ZapMenuItem(PREFIX + ".topmenu.report.title");
            runReportMenu.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            runReport();
                        }
                    });
        }
        return runReportMenu;
    }

    private SiteNode getWavsepNode(SiteNode node) {
        if (node.getNodeName().endsWith(wavsepNodeName) && node.getChildCount() > 0) {
            return node;
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            SiteNode n = getWavsepNode((SiteNode) node.getChildAt(i));
            if (n != null) {
                return n;
            }
        }
        return null;
    }

    private int[] wavsepReport(SiteNode node) {
        if (node.getChildCount() > 0) {
            // total up score from children
            int pass = 0;
            int fail = 0;
            for (int i = 0; i < node.getChildCount(); i++) {
                int[] result = wavsepReport((SiteNode) node.getChildAt(i));
                pass += result[0];
                fail += result[1];
            }
            int passRate = 0;
            if (pass + fail > 0) {
                passRate = pass * 100 / (pass + fail);
            }
            getOutputPane()
                    .append(
                            node.getHierarchicNodeName()
                                    + ", "
                                    + pass
                                    + ", "
                                    + fail
                                    + ", "
                                    + passRate
                                    + "%\n");

            // create the html
            StringBuilder sb = new StringBuilder();
            String name = node.getHierarchicNodeName();
            int i = name.indexOf("/wavsep/");

            sb.append("<tr><td>");
            sb.append(node.getHierarchicNodeName().substring(i + 8));
            sb.append("</td><td align=\"right\">");
            sb.append(pass);
            sb.append("</td><td align=\"right\">");
            sb.append(fail);
            sb.append("</td><td align=\"right\">");
            sb.append(passRate);
            sb.append("%</td><td><font style=\"BACKGROUND-COLOR: GREEN\">");
            for (int j = 0; j < passRate; j++) {
                sb.append("&nbsp;");
            }
            sb.append("</font><font style=\"BACKGROUND-COLOR: RED\">");
            if (fail > 0) {
                // So that pass=0 and fail=0 are more obvious
                for (int j = 0; j < (100 - passRate); j++) {
                    sb.append("&nbsp;");
                }
            }
            sb.append("</font></td></tr>");
            this.summaryHtmlList.add(sb.toString());
            return new int[] {pass, fail};
        } else {
            // Calculate scores for this node
            boolean pass = false;
            boolean fail = false;

            StringBuilder passes = new StringBuilder();
            StringBuilder fails = new StringBuilder();
            StringBuilder unknowns = new StringBuilder();
            StringBuilder ignores = new StringBuilder();

            for (Alert alert : node.getAlerts()) {
                String shortForm = null;
                for (String[] sf : SHORT_FORMS) {
                    if (alert.getName().equalsIgnoreCase(sf[0])) {
                        shortForm = sf[1];
                        break;
                    }
                }
                if (shortForm == null) {
                    // Wont be a rule for it
                    missingShortForms.add(alert.getName());
                    continue;
                }
                boolean foundRule = false;
                for (String[] rule : RULES) {
                    if (node.getHierarchicNodeName().contains(rule[0])
                            && shortForm.equals(rule[1])) {
                        if (rule[2].equals(PASS)) {
                            foundRule = true;
                            pass = true;
                            if (!passes.toString().contains(shortForm + " ")) {
                                passes.append(shortForm);
                                passes.append(" ");
                            }
                        } else if (rule[2].equals(FAIL)) {
                            foundRule = true;
                            fail = true;
                            if (!fails.toString().contains(shortForm + " ")) {
                                fails.append(shortForm);
                                fails.append(" ");
                            }
                        } else if (rule[2].equals(IGNORE)) {
                            foundRule = true;
                            if (!ignores.toString().contains(shortForm + " ")) {
                                ignores.append(shortForm);
                                ignores.append(" ");
                            }
                            // Ignore ;)
                        } else {
                            System.out.println(
                                    "Unextected rule "
                                            + rule[0]
                                            + " | "
                                            + rule[1]
                                            + " | "
                                            + rule[2]);
                        }
                        break;
                    }
                }
                if (!foundRule) {
                    // System.out.println("No rule for " + node.getHierarchicNodeName() + " " +
                    // shortForm);
                    unknowns.append(shortForm);
                    unknowns.append(" ");
                }
            }
            if (!node.getNodeName().contains("Case")) {
                if ((node.getNodeName().contains("index") && node.getNodeName().endsWith(".jsp"))
                        || node.getNodeName().endsWith(".ini")
                        || node.getNodeName().endsWith(".html")
                        || node.getNodeName().endsWith(".txt")) {
                    // Print out so we can check it
                    System.out.println("Ignoring " + node.getHierarchicNodeName());
                    return new int[] {0, 0};
                }
            }
            if (!pass && !fail) {
                if (node.getNodeName().contains("Case")) {
                    if (node.getHierarchicNodeName().contains("FalsePositive")) {
                        // System.out.println("Passing " + node.getHierarchicNodeName());
                        pass = true;
                    } else {
                        // System.out.println("Failing " + node.getHierarchicNodeName());
                        fail = false;
                    }
                }
            }
            // Generate detailed report
            String name = node.getHierarchicNodeName();
            int i = name.indexOf("/wavsep/");

            detailHtml.append("<tr><td>");
            detailHtml.append(node.getHierarchicNodeName().substring(i + 8));
            detailHtml.append("</td><td>");
            if (pass) {
                detailHtml.append(
                        "<font style=\"BACKGROUND-COLOR: GREEN\">&nbsp;PASS&nbsp</font></td><td>");
            } else {
                detailHtml.append(
                        "<font style=\"BACKGROUND-COLOR: RED\">&nbsp;FAIL&nbsp</font></td><td>");
            }
            detailHtml.append(passes.toString());
            if (passes.toString().length() == 0) {
                detailHtml.append("&nbsp;");
            }
            detailHtml.append("</td><td>");
            detailHtml.append(fails.toString());
            if (fails.toString().length() == 0) {
                detailHtml.append("&nbsp;");
            }
            detailHtml.append("</td><td>");
            detailHtml.append(ignores.toString());
            if (ignores.toString().length() == 0) {
                detailHtml.append("&nbsp;");
            }
            detailHtml.append("</td><td>");
            detailHtml.append(unknowns.toString());
            if (unknowns.toString().length() == 0) {
                detailHtml.append("&nbsp;");
            }
            detailHtml.append("</td></tr>");
            detailHtml.append("\n");

            if (pass) {
                return new int[] {1, 0};
            } else {
                return new int[] {0, 1};
            }

            // System.out.println("WavsepRpt child " + node.getHierarchicNodeName() + ", " + pass +
            // ", " + fail);
        }
        // System.out.println("WavsepRpt wavsepReport done " + node.getHierarchicNodeName() +
        // "pass=" + pass + " fail=" + fail);
    }

    private void runReport() {
        getStatusPanel().setTabFocus();
        // Clear previous results
        getOutputPane().setText("");

        // Walk the tree looking for a 'wavsep' node
        SiteNode wavsepNode =
                this.getWavsepNode(Model.getSingleton().getSession().getSiteTree().getRoot());
        if (wavsepNode == null) {
            getOutputPane().setText("Failed to find wavsep node :(");
            return;
        }
        // total score

        int pass = 0;
        int fail = 0;
        for (int i = 0; i < wavsepNode.getChildCount(); i++) {
            int[] result = wavsepReport((SiteNode) wavsepNode.getChildAt(i));
            pass += result[0];
            fail += result[1];
        }
        int passRate = 0;
        if (pass + fail > 0) {
            passRate = pass * 100 / (pass + fail);
        }
        getOutputPane().append("TOTALS " + pass + ", " + fail + ", " + passRate + "%\n");

        Iterator<String> msfIter = missingShortForms.iterator();
        while (msfIter.hasNext()) {
            System.out.println("Missing short form: " + msfIter.next());
        }

        // Print the report to a file
        File htmlFile = new File("Wavsep-test-report.html");
        try {
            PrintWriter pw = new PrintWriter(htmlFile);

            pw.println("<html><head><title>ZAP Wavsep Report</title></head><body>");
            pw.println(
                    "<h1><img src=\"https://raw.githubusercontent.com/zaproxy/zaproxy/develop/zap/src/main/resources/resource/zap64x64.png\" align=\"middle\">OWASP ZAP wavsep results</h1>");
            pw.println("Generated TBA");
            pw.println("<h3>Total Score " + passRate + "%</h3>");
            pw.println("<br/>");

            // Summary first
            pw.println("<table border=\"1\">");
            pw.println(
                    "<tr><th>Top Level</th><th>Pass</th><th>Fail</th><th>Score</th><th>Chart</th>");
            // Loop backwards through the summary list
            for (int j = summaryHtmlList.size() - 1; j >= 0; j--) {
                pw.println(summaryHtmlList.get(j));
            }
            pw.println("</table>");
            pw.println("</body>");
            pw.println("<br/>");

            // Then the details
            pw.println("<h3>Detailed Results</h3>");
            pw.println("<table border=\"1\">");
            pw.println(
                    "<tr><th>Page</th><th>Result</th><th>Pass</th><th>Fail</th><th>Ignore</th><th>Other</th>");
            pw.println(this.detailHtml.toString());
            pw.println("</table>");

            pw.close();

            System.out.println("Successfully wrote to " + htmlFile.getAbsolutePath() + " ??");
            DesktopUtils.openUrlInBrowser(new URI("file://" + htmlFile.getAbsolutePath()));

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
