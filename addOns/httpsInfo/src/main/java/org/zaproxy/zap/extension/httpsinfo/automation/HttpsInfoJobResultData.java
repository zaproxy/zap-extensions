/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.httpsinfo.automation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.httpsinfo.CertificateFound;
import org.zaproxy.zap.extension.httpsinfo.CipherSuite;
import org.zaproxy.zap.extension.httpsinfo.ExtensionHttpsInfo;
import org.zaproxy.zap.extension.httpsinfo.HttpsInfoTableModel;

public class HttpsInfoJobResultData extends JobResultData {

    public static final String DATA_KEY = "httpsInfoData";

    private Map<String, List<HttpsInfoData>> siteHttpsInfoMap = new HashMap<>();

    public HttpsInfoJobResultData(String jobName) {
        super(jobName);

        ExtensionHttpsInfo ext =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHttpsInfo.class);

        for (String site : ext.getSites()) {
            List<HttpsInfoData> httpsInfoDataList = new ArrayList<>();
            HttpsInfoTableModel model = ext.getHttpsInfoModelForSite(site);
            for (CertificateFound certFound : model.getCertificates()) {
                httpsInfoDataList.add(new HttpsInfoData(certFound));
            }
            siteHttpsInfoMap.put(site, httpsInfoDataList);
        }
    }

    public List<HttpsInfoData> getHttpsInfoModelForSite(String site) {
        List<HttpsInfoData> data = this.siteHttpsInfoMap.get(site);
        if (data == null) {
            return Collections.emptyList();
        }
        return data;
    }

    public Set<String> getAllSites() {
        return this.siteHttpsInfoMap.keySet();
    }

    @Override
    public String getKey() {
        return DATA_KEY;
    }

    public static class HttpsInfoData {
        private final String subjectDN;
        private final String signingAlgorithm;
        private final String certificateFingerPrint;
        private final String issuerDN;
        private final String notValidBefore;
        private final String notValidAfter;
        private final String certificateSerialNumber;
        private final String certificateVersion;
        private final String selfSignedCertificate;
        private final String trustState;
        private final String validState;

        private final List<CipherSuite> cipherSuites;


        public HttpsInfoData(CertificateFound certificateFound) {
            subjectDN = certificateFound.getCertification().getSubjectDN();
            signingAlgorithm = certificateFound.getCertification().getSigningAlgorithm();
            certificateFingerPrint = certificateFound.getCertification().getCertificateFingerPrint();
            issuerDN = certificateFound.getCertification().getIssuerDN();
            notValidBefore = certificateFound.getCertification().getNotValidBefore();
            notValidAfter = certificateFound.getCertification().getNotValidAfter();
            certificateSerialNumber = certificateFound.getCertification().getCertificateSerialNumber();
            certificateVersion = certificateFound.getCertification().getCertificateVersion();
            selfSignedCertificate = certificateFound.getCertification().getSelfSignedCertificate();
            trustState = certificateFound.getCertification().getTrustState();
            validState = certificateFound.getCertification().getValidState();

            cipherSuites = certificateFound.getCipherSuites();
        }

        public String getSubjectDN() {
            return subjectDN;
        }

        public String getSigningAlgorithm() {
            return signingAlgorithm;
        }

        public String getCertificateFingerPrint() {
            return certificateFingerPrint;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        public String getNotValidBefore() {
            return notValidBefore;
        }

        public String getNotValidAfter() {
            return notValidAfter;
        }

        public String getCertificateSerialNumber() {
            return certificateSerialNumber;
        }

        public String getCertificateVersion() {
            return certificateVersion;
        }

        public String getSelfSignedCertificate() {
            return selfSignedCertificate;
        }

        public String getValidState(){ return validState;}

        public String getTrustState(){ return trustState;}

        public List<CipherSuite> getCipherSuites() {
            return cipherSuites;
        }

    }
}
