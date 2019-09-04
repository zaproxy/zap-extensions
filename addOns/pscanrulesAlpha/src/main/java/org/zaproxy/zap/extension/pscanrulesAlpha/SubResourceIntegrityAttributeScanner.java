package org.zaproxy.zap.extension.pscanrulesAlpha;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import java.util.Arrays;
import java.util.List;

import static net.htmlparser.jericho.HTMLElementName.LINK;
import static net.htmlparser.jericho.HTMLElementName.SCRIPT;

/** Detect missing attribute integrity in tag <script> */
public class SubResourceIntegrityAttributeScanner extends PluginPassiveScanner {
  /** Prefix for internationalized messages used by this rule */
  private static final String MESSAGE_PREFIX = "pscanalpha.sri-integrity.";

  // From
  // https://w3c.github.io/webappsec-subresource-integrity/#verification-of-html-document-subresources
  // To support integrity metadata for some of these elements, a new integrity attribute is added to
  // the list of content attributes for the link and script elements.
  // Note: A future revision of this specification is likely to include integrity support for all
  // possible subresources, i.e., a, audio, embed, iframe, img, link, object, script, source, track,
  // and video elements.
  private static final List<String> SUPPORTED_ELEMENTS = Arrays.asList(SCRIPT, LINK);

  private PassiveScanThread parent;

  @Override
  public void scanHttpRequestSend(HttpMessage msg, int id) {
    // do nothing
  }

  @Override
  public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
    List<Element> sourceElements = source.getAllElements();
    boolean unsafeElement =
        sourceElements.stream()
            .filter(e -> SUPPORTED_ELEMENTS.contains(e.getName()))
            .anyMatch(
                e ->
                    e.getAttributeValue("integrity") == null
                        && !e.getAttributeValue("src")
                            .matches(
                                "^https://[^/]*" + msg.getRequestHeader().getHostName() + "/.*"));

    if (unsafeElement) {
      Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName());

      alert.setDetail(
          getString("desc"),
          msg.getRequestHeader().getURI().toString(),
          "", // param
          "", // attack
          "", // other info
          getString("soln"),
          getString("refs"),
          "",
          693, // Protection Mechanism Failure
          -1, // No
          msg);
      parent.raiseAlert(id, alert);
    }
  }

  @Override
  public void setParent(PassiveScanThread parent) {
    this.parent = parent;
  }

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
