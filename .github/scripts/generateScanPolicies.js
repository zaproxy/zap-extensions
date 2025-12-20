// This is a ZAP standalone script - it will only run in ZAP.
// It generates the scan policies for https://github.com/zaproxy/zap-extensions/tree/main/addOns/scanpolicies etc
// The policies are created after starting a ZAP nightly release with the '-addoninstall ascanrulesAlpha' option.

const FileWriter = Java.type("java.io.FileWriter");
const PrintWriter = Java.type("java.io.PrintWriter");
const PolicyTag = Java.type("org.zaproxy.addon.commonlib.PolicyTag");
const UTF_8 = Java.type("java.nio.charset.StandardCharsets").UTF_8;
const StringEscapeUtils = Java.type(
  "org.apache.commons.text.StringEscapeUtils"
);

const extAscan = control
  .getExtensionLoader()
  .getExtension(org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

const plugins = extAscan
  .getPolicyManager()
  .getDefaultScanPolicy()
  .getPluginFactory()
  .getAllPlugin()
  .toArray()
  .sort(function (a, b) {
    return a.getId() - b.getId();
  });

const INDENT = "    ";

PolicyTag.values().forEach((currentTag) => {
  const policyFilePath =
    "/zap/wrk/zap-extensions/addOns/XXXXX/src/main/zapHomeFiles/policies/".replace(
      "XXXXX",
      currentTag.getAddonId()
    ) + currentTag.getFileName();
  print(policyFilePath);
  // Create the policy
  const fw = new FileWriter(policyFilePath, UTF_8);
  const pw = new PrintWriter(fw);
  pw.println('<?xml version="1.0" encoding="UTF-8" standalone="no"?>');
  pw.println("<configuration>");
  pw.println(
    INDENT +
      "<policy>" +
      StringEscapeUtils.escapeXml11(currentTag.getPolicyName()) +
      "</policy>"
  );
  pw.println(INDENT + "<statsId>std-" + currentTag.name().toLowerCase().replace('_', '-') + "</statsId>");
  pw.println(INDENT + "<readonly>true</readonly>");
  pw.println(INDENT + "<locked>true</locked>");
  pw.println(INDENT + "<scanner>");
  pw.println(INDENT.repeat(2) + "<level>MEDIUM</level>");
  pw.println(INDENT.repeat(2) + "<strength>MEDIUM</strength>");
  pw.println(INDENT + "</scanner>");
  pw.println(INDENT + "<plugins>");

  plugins.forEach((plugin) => {
    try {
      if (
        plugin.getAlertTags() != null &&
        plugin.getAlertTags().keySet().contains(currentTag.getTag())
      ) {
        pw.println(INDENT.repeat(2) + "<p" + plugin.getId() + ">");
        pw.println(
          INDENT.repeat(3) +
            "<name>" +
            StringEscapeUtils.escapeXml11(plugin.getName()) +
            "</name>"
        );
        pw.println(INDENT.repeat(3) + "<enabled>true</enabled>");
        pw.println(INDENT.repeat(2) + "</p" + plugin.getId() + ">");
      }
    } catch (e) {
      print(e);
      control.setExitStatus(
        1,
        "An exception was encountered while generating the scan policy(ies)."
      );
    }
  });
  pw.println(INDENT + "</plugins>");
  pw.println("</configuration>");
  pw.close();
});
