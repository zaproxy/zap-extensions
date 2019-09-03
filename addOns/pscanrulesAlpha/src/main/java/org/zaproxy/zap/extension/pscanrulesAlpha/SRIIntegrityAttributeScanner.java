package org.zaproxy.zap.extension.pscanrulesAlpha;

import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Detect missing attribute integrity in tag <script> */
public class SRIIntegrityAttributeScanner extends PluginPassiveScanner {
  /** Prefix for internationalized messages used by this rule */
  private static final String MESSAGE_PREFIX = "pscanalpha.sri-integrity.";

  @Override
  public void scanHttpRequestSend(HttpMessage msg, int id) {
      // do nothing
  }

  @Override
  public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

  }

  @Override
  public void setParent(PassiveScanThread parent) {}

  @Override
  public String getName() {
    return getString("name");
  }

  private String getString(String param) {
    return Constant.messages.getString(MESSAGE_PREFIX + param);
  }

  @Override
  public int getPluginId() {
    return 90003;
  }
}
