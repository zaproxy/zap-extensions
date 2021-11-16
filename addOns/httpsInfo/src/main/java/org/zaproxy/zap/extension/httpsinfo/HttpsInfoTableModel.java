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
package org.zaproxy.zap.extension.httpsinfo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Vector;
import javax.swing.table.AbstractTableModel;

import org.parosproxy.paros.Constant;

public class HttpsInfoTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final Vector<String> columnNames;
    private List<CertificateFound> certifications = new ArrayList<>();

    private int lastAddedRow;
    private int lastEditedRow;

    public HttpsInfoTableModel() {
        super();
        columnNames = new Vector<>();
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.subjectDN"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.signingAlgorithm"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.certificateFingerPrint"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.issuerDN"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.notValidBefore"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.notValidAfter"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.certificateSerialNumber"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.certificateVersion"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.selfSignedCertificate"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.cipherSuites"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.trusted"));
        columnNames.add(Constant.messages.getString("httpsinfo.table.header.valid"));

        certifications = Collections.synchronizedList(new ArrayList<>());

        lastAddedRow = -1;
        lastEditedRow = -1;
    }

    @Override
    public int getColumnCount() {
        return columnNames.size();
    }

    @Override
    public int getRowCount() {
        return certifications.size();
    }

    @Override
    public String getColumnName(int col) {
        return columnNames.get(col);
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object obj = null;
        if (row >= certifications.size()) {
            return null;
        }
        CertificateFound certification = certifications.get(row);
        switch (col) {
            case 0:
                obj = certification.getCertification().getSubjectDN();
                break;
            case 1:
                obj = certification.getCertification().getSigningAlgorithm();
                break;
            case 2:
                obj = certification.getCertification().getCertificateFingerPrint();
                break;
            case 3:
                obj = certification.getCertification().getIssuerDN();
                break;
            case 4:
                obj = certification.getCertification().getNotValidBefore();
                break;
            case 5:
                obj = certification.getCertification().getNotValidAfter();
                break;
            case 6:
                obj = certification.getCertification().getCertificateSerialNumber();
                break;
            case 7:
                obj = certification.getCertification().getCertificateVersion();
                break;
            case 8:
                obj = certification.getCertification().getSelfSignedCertificate();
                break;
            case 9:
                obj = certification.getCipherSuite();
                break;
            case 10:
                obj = certification.getCertification().getTrustState();
                break;
            case 11:
                obj = certification.getCertification().getValidState();
                break;
        }
        return obj;
    }

    public CertificateFound getCertificateAtRow(int row) {
        return certifications.get(row);
    }

    public void addCertificate(CertificateFound certificate) {
        lastAddedRow = -1;

        for (int i = 0; i < certifications.size(); i++) {
            int cmp =
                    certificate.getCertification()
                            .getSubjectDN()
                            .toLowerCase()
                            .compareTo(certifications.get(i).getCertification().getSubjectDN().toLowerCase());
            if (cmp < 0) {
                certifications.add(i, certificate);
                this.fireTableRowsInserted(i, i);

                lastAddedRow = i;
                return;

            } else if (cmp == 0) {
                // Already matches, so ignore
                CertificateFound existing = certifications.get(i);
                lastAddedRow = i;
                return;
            }
        }

        if (!certifications.contains(certificate)) {
            certifications.add(certificate);
            this.fireTableRowsInserted(certifications.size() - 1, certifications.size() - 1);

            lastAddedRow = certifications.size() - 1;
        }
    }

    public int getLastAddedRow() {
        return lastAddedRow;
    }

    public int getLastEditedRow() {
        return lastEditedRow;
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Class<? extends Object> getColumnClass(int c) {
        switch (c) {
            case 0:
                return String.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            case 4:
                return String.class;
            case 5:
                return String.class;
            case 6:
                return String.class;
            case 7:
                return String.class;
            case 8:
                return String.class;
            case 9:
                return String.class;
            case 10:
                return String.class;
            case 11:
                return String.class;
        }
        return null;
    }

    public void removeAllElements() {
        certifications.clear();
    }

    public List<CertificateFound> getCertificates() {
        return certifications;
    }

    public Certification getCertificate(int row) {
        return certifications.get(row).getCertification();
    }
}
