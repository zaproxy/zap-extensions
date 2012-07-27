/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2010 psiinon@gmail.com
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
package org.zaproxy.zap.extension.alertReport;

import org.parosproxy.paros.common.AbstractParam;

/**
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class AlertReportExportParam extends AbstractParam {

	private static final String FORMAT_REPORT = "reportexport.format";
	private static final String TITLE_REPORT = "reportexport.titleReport";
	private static final String LOGO_FILE_NAME = "reportexport.logoFileName";
	private static final String DOCUMENT_ATTACH_FILE_NAME = "reportexport.documentAttach";
	private static final String WORKING_DIR_IMAGES = "reportexport.workingDir";
	private static final String CUSTOMER_NAME = "reportexport.customerName";
	private static final String CONFIDENTIAL_TEXT = "reportexport.confidentialText";
	private static final String PDF_KEYWORDS = "reportexport.pdfKeywods";
	private static final String AUTHOR_NAME = "reportexport.authorName";
	private static final String COMPANY_NAME = "reportexport.companyName";
	
	
	
	public static final String DEFAULT_TITLE_REPORT = "Report of alert ethical hacking";
	public static final String DEFAULT_CUSTOMER_NAME = "Customer Name";
	public static final String DEFAULT_CONFIDENTIAL_TEXT = "This document is CONFIDENTIAL USE ONLY and for whom it is addressed. Contains information that is copyrighted by COMPANYNAME, so that its contents may not be copied, posted, disclosed or used by third parties in any way not expressly authorized by COMPANYNAME. The reception and use of this document by the recipient, explicitly implies acceptance of this Clause. In the same sense COMPANYNAME, treated as CONFIDENTIAL USE ONLY and for the data it receives and if the proposed work done before the start of them signed the corresponding Confidentiality Agreement.";
	public static final String DEFAULT_PDF_KEYWORDS = "report alert,pentest,security";
	public static final String DEFAULT_WORKING_DIR_IMAGES = "";
	public static final String DEFAULT_DOCUMENT_ATTACH_FILE_NAME = "";
	public static final String DEFAULT_LOGO_FILE_NAME = "";
	public static final String DEFAULT_AUTHOR_NAME = "Author Name";
	public static final String DEFAULT_COMPANY_NAME = "Company Name";
	public static final String DEFAULT_FORMAT_REPORT = "PDF";

	public static final String EMPTY_STRING = "";
		
	private String titleReport = DEFAULT_TITLE_REPORT;
	private String logoFileName = DEFAULT_LOGO_FILE_NAME;
	private String documentAttach = DEFAULT_DOCUMENT_ATTACH_FILE_NAME;
	private String workingDirImages = DEFAULT_WORKING_DIR_IMAGES;
	private String customerName = DEFAULT_CUSTOMER_NAME;
	private String confidentialText = DEFAULT_CONFIDENTIAL_TEXT;
	private String pdfKeywords = DEFAULT_PDF_KEYWORDS;
	private String authorName = DEFAULT_AUTHOR_NAME;
	private String companyName = DEFAULT_COMPANY_NAME;
	private String formatReport = DEFAULT_FORMAT_REPORT;
	
    public String getCompanyName() {
		return companyName;
	}

	public void setCompanyName(String companyName) {
		this.companyName = companyName;
		getConfig().setProperty(COMPANY_NAME, this.companyName);
	}

	public String getDocumentAttach() {
		return documentAttach;
	}

	public void setDocumentAttach(String documentAttach) {
		this.documentAttach = documentAttach;
		getConfig().setProperty(DOCUMENT_ATTACH_FILE_NAME, this.documentAttach);
	}
	
	public String getFormatReport() {
		return formatReport;
	}

	public void setFormatReport(String formatReport) {
		this.formatReport = formatReport;
		getConfig().setProperty(FORMAT_REPORT, this.formatReport);
	}

	/**
     * @param rootElementName
     */
    public AlertReportExportParam() {
    }

    @Override
    protected void parse(){
		try {
			titleReport = getConfig().getString(TITLE_REPORT, DEFAULT_TITLE_REPORT);
			logoFileName = getConfig().getString(LOGO_FILE_NAME, DEFAULT_LOGO_FILE_NAME);
			workingDirImages = getConfig().getString(WORKING_DIR_IMAGES, DEFAULT_WORKING_DIR_IMAGES);
			customerName = getConfig().getString(CUSTOMER_NAME, DEFAULT_CUSTOMER_NAME);
			confidentialText = getConfig().getString(CONFIDENTIAL_TEXT, DEFAULT_CONFIDENTIAL_TEXT);
			pdfKeywords = getConfig().getString(PDF_KEYWORDS, DEFAULT_PDF_KEYWORDS);
			authorName = getConfig().getString(AUTHOR_NAME, DEFAULT_AUTHOR_NAME);
			companyName = getConfig().getString(COMPANY_NAME, DEFAULT_COMPANY_NAME);
			formatReport = getConfig().getString(FORMAT_REPORT, DEFAULT_FORMAT_REPORT);
			documentAttach = getConfig().getString(DOCUMENT_ATTACH_FILE_NAME, DEFAULT_DOCUMENT_ATTACH_FILE_NAME);


		} catch (Exception e) {}
    }

   
    
    public String getTitleReport() {
		return titleReport;
	}

	public void setTitleReport(String titleReport) {
		this.titleReport = titleReport;
		getConfig().setProperty(TITLE_REPORT, this.titleReport);
	}

	public String getLogoFileName() {
		return logoFileName;
	}

	public void setLogoFileName(String logoFileName) {
		this.logoFileName = logoFileName;
		getConfig().setProperty(LOGO_FILE_NAME, this.logoFileName);
	}

	public String getWorkingDirImages() {
		return workingDirImages;
	}

	public void setWorkingDirImages(String workingDirImages) {
		this.workingDirImages = workingDirImages;
		getConfig().setProperty(WORKING_DIR_IMAGES, this.workingDirImages);
	}

	public String getCustomerName() {
		return customerName;
	}

	public void setCustomerName(String customerName) {
		this.customerName = customerName;
		getConfig().setProperty(CUSTOMER_NAME, this.customerName);
	}

	public String getConfidentialText() {
		return confidentialText;
	}

	public void setConfidentialText(String confidentialText) {
		this.confidentialText = confidentialText;
		getConfig().setProperty(CONFIDENTIAL_TEXT, this.confidentialText);
	}

	public String getPdfKeywords() {
		return pdfKeywords;
	}

	public void setPdfKeywords(String pdfKeywords) {
		this.pdfKeywords = pdfKeywords;
		getConfig().setProperty(PDF_KEYWORDS, this.pdfKeywords);
	}

	public String getAuthorName() {
		return authorName;
	}

	public void setAuthorName(String authorName) {
		this.authorName = authorName;
		getConfig().setProperty(AUTHOR_NAME, this.authorName);
	}

    

}
