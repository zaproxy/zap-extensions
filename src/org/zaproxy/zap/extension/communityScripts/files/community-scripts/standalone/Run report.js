// Script for generating a ZAP report in xml of html format

// set up some useful vars
model = org.parosproxy.paros.model.Model().getSingleton();
rls = new org.parosproxy.paros.extension.report.ReportLastScan();

// code for generating an xml report and storing it in a var
sb = new java.lang.StringBuilder();
// this call generates an xml report - you dont need it if you want the html report generated below
rls.generate(sb, model);
// sb now contains the raw xml report
// print(sb);

// alternative code for generating an html report and storing it in a file
// xsl is the default xslt file
xsl = org.parosproxy.paros.Constant.getZapInstall() + "/xml/report.html.xsl"
// change html to be the name of the report file you want to creat
html = org.parosproxy.paros.Constant.getZapHome() + "/report.html"
// create the report
rpt = rls.generate(html, model, xsl)
// display the report in a browser - this is just to prove it works ;)
org.zaproxy.zap.utils.DesktopUtils.openUrlInBrowser(rpt.toURI());