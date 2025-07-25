/*
 * The ZAP plug-in wrapper for Veggiespam's Image Location and Privacy Scanner
 * class. Passively scans an image data stream (jpg/png/etc) and reports if the
 * image contains embedded location or privacy information, such as Exif GPS,
 * IPTC codes, and some proprietary camera codes which may contain things like
 * serial numbers.
 *
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / https://www.veggiespam.com/ils/
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
package org.zaproxy.zap.extension.imagelocationscanner;

import com.veggiespam.imagelocationscanner.ILS;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * The ZAP plug-in wrapper for Veggiespam's Image Location and Privacy Scanner class. Passively
 * scans an image data stream (jpg/png/etc) and reports if the image contains embedded location or
 * privacy information, such as Exif GPS, IPTC codes, and some proprietary camera codes which may
 * contain things like serial numbers.
 *
 * @author Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 1.2
 * @see https://www.veggiespam.com/ils/
 */
public class ImageLocationScanRule extends PluginPassiveScanner {
    private static final Logger LOGGER = LogManager.getLogger(ImageLocationScanRule.class);
    private static final String MESSAGE_PREFIX = "imagelocationscanner.";
    public static final int PLUGIN_ID = 10103;
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/image-location-and-privacy-scanner/"
                + "#id-"
                + PLUGIN_ID;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = 0;
        if (LOGGER.isDebugEnabled()) {
            start = System.currentTimeMillis();
        }

        // Mnemonic: CT ==> Content-Type
        String CT = msg.getResponseHeader().getHeader("Content-Type");
        if (null == CT) {
            CT = "";
        } else {
            CT = CT.toLowerCase();
        }

        URI uri = msg.getRequestHeader().getURI();
        String url = uri.toString();
        String fileName;
        try {
            fileName = uri.getName();
            if (fileName == null) {
                fileName = "";
            }
        } catch (URIException e) {
            // e.printStackTrace();
            // If we cannot decode the URL, then just set filename to empty.
            fileName = "";
        }
        String extension = "";
        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            extension = fileName.substring(i + 1).toLowerCase();
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("\tCT: {} ext: {} url: {} fileName: {}", CT, extension, url, fileName);
        }

        // everything is already lowercase
        if (CT.startsWith("image/jpeg")
                || CT.startsWith("image/jpg")
                || extension.equals("jpeg")
                || extension.equals("jpg")
                || CT.startsWith("image/png")
                || extension.equals("png")
                || CT.startsWith("image/heif")
                || extension.equals("heif")
                || CT.startsWith("image/tiff")
                || extension.equals("tiff")
                || extension.equals("tif")) {

            String hasGPS =
                    ILS.scanForLocationInImage(
                            msg.getResponseBody().getBytes(), ILS.OutputFormat.out_text);

            if (!hasGPS.isEmpty()) {
                buildAlert(hasGPS).raise();
            }
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
        }
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getAlertTitle() {
        return Constant.messages.getString(MESSAGE_PREFIX + "alerttitle");
    }

    public String getAlertDetailPrefix() {
        return Constant.messages.getString(MESSAGE_PREFIX + "alertDetailPrefix");
    }

    public int getCategory() {
        return Category.INFO_GATHER;
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    public String getAuthor() {
        return ILS.pluginAuthor;
    }

    private AlertBuilder buildAlert(String gpsDetails) {
        return newAlert()
                .setName(getAlertTitle())
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(getAlertDetailPrefix() + "\n" + gpsDetails)
                .setCweId(200) // CWE-200: Information Exposure
                .setWascId(13); // WASC-13: Information Leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();

        // Single line example
        // String gpsDetails = "\n  Location:: \n    Exif_GPS: 40° 50' 19\", -74° 12' 33\"";

        // Multi-line, real-world example: Panasonic camera image with GPS and face recognition from
        // https://raw.githubusercontent.com/drewnoakes/metadata-extractor-images/master/jpg/Panasonic%20DMC-TZ10.jpg
        final String gpsDetails =
                "\n"
                        + "  Location::\n"
                        + "    Exif_GPS: 53° 8' 49.65\", 8° 10' 45.1\"\n"
                        + "    Panasonic: City = OLDENBURG (OLDB.)\n"
                        + "    Panasonic: Country = GERMANY\n"
                        + "    Panasonic: State = OLDENBURG (OLDB.)\n"
                        + "  Privacy::\n"
                        + "    Panasonic: Face Recognition Info = Face 1: x: 142 y: 120 width: 76 height: 76 name: NIELS age: 31 years 7 months 15 days\n"
                        + "    Panasonic: Internal Serial Number = F541005110191";

        alerts.add(buildAlert(gpsDetails).build());
        return alerts;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        if (historyType == HistoryReference.TYPE_HIDDEN) {
            // Scan hidden images, if the scanner is enabled it should scan.
            return true;
        }
        return super.appliesToHistoryType(historyType);
    }
}
