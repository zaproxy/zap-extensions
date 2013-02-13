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

import java.util.ResourceBundle;

import org.parosproxy.paros.Constant;
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
	
	public static final String DEFAULT_WORKING_DIR_IMAGES = "";
	public static final String DEFAULT_DOCUMENT_ATTACH_FILE_NAME = "";
	public static final String DEFAULT_LOGO_FILE_NAME = "";
	public static final String EMPTY_STRING = "";
		
	private String titleReport;
	private String logoFileName;
	private String documentAttach = DEFAULT_DOCUMENT_ATTACH_FILE_NAME;
	private String workingDirImages = DEFAULT_WORKING_DIR_IMAGES;
	private String customerName;
	private String confidentialText;
	private String pdfKeywords;
	private String authorName;
	private String companyName;
	private String formatReport;
	
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
    	ResourceBundle messages = ResourceBundle.getBundle(
        		this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());
		titleReport = getConfig().getString(TITLE_REPORT, messages.getString("alertreport.export.report.title.default"));
		logoFileName = getConfig().getString(LOGO_FILE_NAME, DEFAULT_LOGO_FILE_NAME);
		workingDirImages = getConfig().getString(WORKING_DIR_IMAGES, DEFAULT_WORKING_DIR_IMAGES);
		customerName = getConfig().getString(CUSTOMER_NAME, messages.getString("alertreport.export.report.title.customername.default"));
		confidentialText = getConfig().getString(CONFIDENTIAL_TEXT, messages.getString("alertreport.export.report.confidentialtext.default"));
		pdfKeywords = getConfig().getString(PDF_KEYWORDS, messages.getString("alertreport.export.report.keywords.default"));
		authorName = getConfig().getString(AUTHOR_NAME,  messages.getString("alertreport.export.report.authorname.default"));
		companyName = getConfig().getString(COMPANY_NAME, messages.getString("alertreport.export.report.companyname.default"));
		formatReport = getConfig().getString(FORMAT_REPORT, messages.getString("alertreport.export.report.formatreport.default"));
		documentAttach = getConfig().getString(DOCUMENT_ATTACH_FILE_NAME, DEFAULT_DOCUMENT_ATTACH_FILE_NAME);
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
