package org.zaproxy.zap.extension.codedx;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.report.ReportLastScan;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.XmlReporterExtension;

public class ReportLastScanHttp extends ReportLastScan {

    ReportLastScanHttp() {
    }

    @Override
    public StringBuilder getExtensionsXML(SiteNode site) {
        StringBuilder extensionXml = new StringBuilder();
        ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
        int extensionCount = loader.getExtensionCount();
        ExtensionAlertHttp extensionHttp = new ExtensionAlertHttp();
        for (int i = 0; i < extensionCount; i++) {
            Extension extension = loader.getExtension(i);
            if (extension instanceof XmlReporterExtension) {
                extensionXml.append(extensionHttp.getXml(site));
            }
        }
        return extensionXml;
    }

}
