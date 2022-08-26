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
package org.zaproxy.addon.commonlib;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** A standard set of alert tags. */
public enum CommonAlertTag {
    // OWASP Top 10 2021
    OWASP_2021_A01_BROKEN_AC(
            "OWASP_2021_A01", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    OWASP_2021_A02_CRYPO_FAIL(
            "OWASP_2021_A02", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    OWASP_2021_A03_INJECTION("OWASP_2021_A03", "https://owasp.org/Top10/A03_2021-Injection/"),
    OWASP_2021_A04_INSECURE_DESIGN(
            "OWASP_2021_A04", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    OWASP_2021_A05_SEC_MISCONFIG(
            "OWASP_2021_A05", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    OWASP_2021_A06_VULN_COMP(
            "OWASP_2021_A06",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    OWASP_2021_A07_AUTH_FAIL(
            "OWASP_2021_A07",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    OWASP_2021_A08_INTEGRITY_FAIL(
            "OWASP_2021_A08",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    OWASP_2021_A09_LOGGING_FAIL(
            "OWASP_2021_A09",
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    OWASP_2021_A10_SSRF(
            "OWASP_2021_A10",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),

    // OWASP Top 10 2017
    OWASP_2017_A01_INJECTION(
            "OWASP_2017_A01", "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html"),
    OWASP_2017_A02_BROKEN_AUTH(
            "OWASP_2017_A02",
            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html"),
    OWASP_2017_A03_DATA_EXPOSED(
            "OWASP_2017_A03",
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html"),
    OWASP_2017_A04_XXE(
            "OWASP_2017_A04",
            "https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html"),
    OWASP_2017_A05_BROKEN_AC(
            "OWASP_2017_A05",
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html"),
    OWASP_2017_A06_SEC_MISCONFIG(
            "OWASP_2017_A06",
            "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html"),
    OWASP_2017_A07_XSS(
            "OWASP_2017_A07",
            "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html"),
    OWASP_2017_A08_INSECURE_DESERIAL(
            "OWASP_2017_A08",
            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html"),
    OWASP_2017_A09_VULN_COMP(
            "OWASP_2017_A09",
            "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html"),
    OWASP_2017_A10_LOGGING_FAIL(
            "OWASP_2017_A10",
            "https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring.html"),

    // OWASP WSTG v4.2
    WSTG_V42_INFO_01_SEARCH_ENGINE(
            "WSTG-v42-INFO-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"),
    WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER(
            "WSTG-v42-INFO-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"),
    WSTG_V42_INFO_03_METAFILE(
            "WSTG-v42-INFO-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"),
    WSTG_V42_INFO_04_ENUMERATE_APPS(
            "WSTG-v42-INFO-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver"),
    WSTG_V42_INFO_05_CONTENT_LEAK(
            "WSTG-v42-INFO-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"),
    WSTG_V42_INFO_06_APP_ENTRY_POINTS(
            "WSTG-v42-INFO-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points"),
    WSTG_V42_INFO_07_APP_EXEC_PATHS(
            "WSTG-v42-INFO-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application"),
    WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK(
            "WSTG-v42-INFO-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"),
    WSTG_V42_INFO_09_FINGERPRINT_WEB_APP(
            "WSTG-v42-INFO-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/09-Fingerprint_Web_Application"),
    WSTG_V42_INFO_10_MAP_APP_ARCHITECTURE(
            "WSTG-v42-INFO-10",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/10-Map_Application_Architecture"),
    WSTG_V42_CONF_01_NETWORK_INFRA(
            "WSTG-v42-CONF-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"),
    WSTG_V42_CONF_02_APP_PLATFORM(
            "WSTG-v42-CONF-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration"),
    WSTG_V42_CONF_03_FILE_EXT_HANDLING(
            "WSTG-v42-CONF-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information"),
    WSTG_V42_CONF_04_BACKUP_FILES(
            "WSTG-v42-CONF-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"),
    WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE(
            "WSTG-v42-CONF-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"),
    WSTG_V42_CONF_06_HTTP_METHODS(
            "WSTG-v42-CONF-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"),
    WSTG_V42_CONF_07_HTTP_STS(
            "WSTG-v42-CONF-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security"),
    WSTG_V42_CONF_08_RIA_CROSS_DOMAIN(
            "WSTG-v42-CONF-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Test_RIA_Cross_Domain_Policy"),
    WSTG_V42_CONF_09_FILE_PERMISSIONS(
            "WSTG-v42-CONF-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission"),
    WSTG_V42_CONF_10_SUBDOMAIN_TAKEOVER(
            "WSTG-v42-CONF-10",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"),
    WSTG_V42_CONF_11_CLOUD_STORAGE(
            "WSTG-v42-CONF-11",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage"),
    WSTG_V42_IDNT_01_ROLE_DEFINITIONS(
            "WSTG-v42-IDNT-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/01-Test_Role_Definitions"),
    WSTG_V42_IDNT_02_USER_REGISTRATION(
            "WSTG-v42-IDNT-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/02-Test_User_Registration_Process"),
    WSTG_V42_IDNT_03_ACCOUNT_PROVISIONING(
            "WSTG-v42-IDNT-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/03-Test_Account_Provisioning_Process"),
    WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION(
            "WSTG-v42-IDNT-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"),
    WSTG_V42_IDNT_05_USERNAME_POLICY(
            "WSTG-v42-IDNT-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/05-Testing_for_Weak_or_Unenforced_Username_Policy"),
    WSTG_V42_ATHN_01_CREDS_NO_CRYPTO(
            "WSTG-v42-ATHN-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel"),
    WSTG_V42_ATHN_02_DEFAULT_CREDS(
            "WSTG-v42-ATHN-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials"),
    WSTG_V42_ATHN_03_WEAK_LOCKOUT(
            "WSTG-v42-ATHN-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism"),
    WSTG_V42_ATHN_04_AUTH_BYPASS(
            "WSTG-v42-ATHN-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema"),
    WSTG_V42_ATHN_05_VULN_REMEMBER_PASSWORD(
            "WSTG-v42-ATHN-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/05-Testing_for_Vulnerable_Remember_Password"),
    WSTG_V42_ATHN_06_CACHE_WEAKNESS(
            "WSTG-v42-ATHN-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"),
    WSTG_V42_ATHN_07_WEAK_PASSWORD_POLICY(
            "WSTG-v42-ATHN-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy"),
    WSTG_V42_ATHN_08_WEAK_SEC_QUESTIONS(
            "WSTG-v42-ATHN-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/08-Testing_for_Weak_Security_Question_Answer"),
    WSTG_V42_ATHN_09_WEAK_CRED_MANAGEMENT(
            "WSTG-v42-ATHN-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities"),
    WSTG_V42_ATHN_10_WEAK_ALT_AUTH(
            "WSTG-v42-ATHN-10",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel"),
    WSTG_V42_ATHZ_01_DIR_TRAVERSAL(
            "WSTG-v42-ATHZ-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"),
    WSTG_V42_ATHZ_02_AUTHZ_BYPASS(
            "WSTG-v42-ATHZ-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema"),
    WSTG_V42_ATHZ_03_PRIV_ESCALATION(
            "WSTG-v42-ATHZ-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation"),
    WSTG_V42_ATHZ_04_IDOR(
            "WSTG-v42-ATHZ-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"),
    WSTG_V42_SESS_01_SESS_MANAGEMENT(
            "WSTG-v42-SESS-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema"),
    WSTG_V42_SESS_02_COOKIE_ATTRS(
            "WSTG-v42-SESS-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes"),
    WSTG_V42_SESS_03_SESS_FIXATION(
            "WSTG-v42-SESS-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation"),
    WSTG_V42_SESS_04_SESS_EXPOSED(
            "WSTG-v42-SESS-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables"),
    WSTG_V42_SESS_05_CSRF(
            "WSTG-v42-SESS-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery"),
    WSTG_V42_SESS_06_WEAK_LOGOUT(
            "WSTG-v42-SESS-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality"),
    WSTG_V42_SESS_07_SESS_TIMEOUT(
            "WSTG-v42-SESS-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_Session_Timeout"),
    WSTG_V42_SESS_08_SESS_PUZZLING(
            "WSTG-v42-SESS-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/08-Testing_for_Session_Puzzling"),
    WSTG_V42_SESS_09_SESS_HIJACK(
            "WSTG-v42-SESS-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/09-Testing_for_Session_Hijacking"),
    WSTG_V42_INPV_01_REFLECTED_XSS(
            "WSTG-v42-INPV-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"),
    WSTG_V42_INPV_02_STORED_XSS(
            "WSTG-v42-INPV-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting"),
    WSTG_V42_INPV_03_VERB_TAMPERING(
            "WSTG-v42-INPV-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering"),
    WSTG_V42_INPV_04_PARAM_POLLUTION(
            "WSTG-v42-INPV-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution"),
    WSTG_V42_INPV_05_SQLI(
            "WSTG-v42-INPV-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection"),
    WSTG_V42_INPV_06_LDAPI(
            "WSTG-v42-INPV-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection"),
    WSTG_V42_INPV_07_XMLI(
            "WSTG-v42-INPV-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"),
    WSTG_V42_INPV_08_SSII(
            "WSTG-v42-INPV-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection"),
    WSTG_V42_INPV_09_XPATH(
            "WSTG-v42-INPV-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection"),
    WSTG_V42_INPV_10_SMTP_IMAP_INJ(
            "WSTG-v42-INPV-10",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection"),
    WSTG_V42_INPV_11_CODE_INJ(
            "WSTG-v42-INPV-11",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection"),
    WSTG_V42_INPV_12_COMMAND_INJ(
            "WSTG-v42-INPV-12",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection"),
    WSTG_V42_INPV_13_FORMAT_STRING(
            "WSTG-v42-INPV-13",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection"),
    WSTG_V42_INPV_14_INCUBATED_VULN(
            "WSTG-v42-INPV-14",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/14-Testing_for_Incubated_Vulnerability"),
    WSTG_V42_INPV_15_HTTP_SPLITTING(
            "WSTG-v42-INPV-15",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling"),
    WSTG_V42_INPV_16_HTTP_REQ(
            "WSTG-v42-INPV-16",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"),
    WSTG_V42_INPV_17_HOST_HEADER(
            "WSTG-v42-INPV-17",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection"),
    WSTG_V42_INPV_18_SSTI(
            "WSTG-v42-INPV-18",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"),
    WSTG_V42_INPV_19_SSRF(
            "WSTG-v42-INPV-19",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery"),
    WSTG_V42_ERRH_01_ERR(
            "WSTG-v42-ERRH-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"),
    WSTG_V42_ERRH_02_STACK(
            "WSTG-v42-ERRH-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces"),
    WSTG_V42_CRYP_01_TLS(
            "WSTG-v42-CRYP-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"),
    WSTG_V42_CRYP_02_PADDING_ORACLE(
            "WSTG-v42-CRYP-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle"),
    WSTG_V42_CRYP_03_CRYPTO_FAIL(
            "WSTG-v42-CRYP-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"),
    WSTG_V42_CRYP_04_WEAK_CRYPTO(
            "WSTG-v42-CRYP-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption"),
    WSTG_V42_BUSL_01_DATA_VALIDATION(
            "WSTG-v42-BUSL-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation"),
    WSTG_V42_BUSL_02_FORGED_REQUESTS(
            "WSTG-v42-BUSL-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests"),
    WSTG_V42_BUSL_03_INTEGRITY_CHECKS(
            "WSTG-v42-BUSL-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/03-Test_Integrity_Checks"),
    WSTG_V42_BUSL_04_PROCESS_TIMING(
            "WSTG-v42-BUSL-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/04-Test_for_Process_Timing"),
    WSTG_V42_BUSL_05_FUNCTION_USE_LIMITS(
            "WSTG-v42-BUSL-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/05-Test_Number_of_Times_a_Function_Can_Be_Used_Limits"),
    WSTG_V42_BUSL_06_WORKFLOW_CIRCUMVENTION(
            "WSTG-v42-BUSL-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows"),
    WSTG_V42_BUSL_07_APP_MISUSE_DEFENSE(
            "WSTG-v42-BUSL-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse"),
    WSTG_V42_BUSL_08_UPLOAD_FILE_TYPES(
            "WSTG-v42-BUSL-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types"),
    WSTG_V42_BUSL_09_UPLOAD_MALICIOUS_FILES(
            "WSTG-v42-BUSL-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files"),
    WSTG_V42_CLNT_01_DOM_XSS(
            "WSTG-v42-CLNT-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting"),
    WSTG_V42_CLNT_02_JS_EXEC(
            "WSTG-v42-CLNT-02",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution"),
    WSTG_V42_CLNT_03_HTML_INJ(
            "WSTG-v42-CLNT-03",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection"),
    WSTG_V42_CLNT_04_OPEN_REDIR(
            "WSTG-v42-CLNT-04",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"),
    WSTG_V42_CLNT_05_CSS_INJ(
            "WSTG-v42-CLNT-05",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection"),
    WSTG_V42_CLNT_06_RESOURCE_MANIPULATION(
            "WSTG-v42-CLNT-06",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation"),
    WSTG_V42_CLNT_07_CORS(
            "WSTG-v42-CLNT-07",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"),
    WSTG_V42_CLNT_08_XS_FLASHING(
            "WSTG-v42-CLNT-08",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing"),
    WSTG_V42_CLNT_09_CLICKJACK(
            "WSTG-v42-CLNT-09",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking"),
    WSTG_V42_CLNT_10_WEBSOCKETS(
            "WSTG-v42-CLNT-10",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets"),
    WSTG_V42_CLNT_11_WEB_MESSAGING(
            "WSTG-v42-CLNT-11",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging"),
    WSTG_V42_CLNT_12_BROWSER_STORAGE(
            "WSTG-v42-CLNT-12",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage"),
    WSTG_V42_CLNT_13_XSSI(
            "WSTG-v42-CLNT-13",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion"),
    WSTG_V42_APIT_01_GRAPHQL(
            "WSTG-v42-APIT-01",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"),
    /**
     * This Alert Tag is used to indicate (Ex: via Example Alerts) alerts (rules) which support user
     * defined payloads via Custom Payloads.
     *
     * @since 1.10.0
     */
    CUSTOM_PAYLOADS("CUSTOM_PAYLOADS", "");

    private String tag;
    private String value;

    private CommonAlertTag(String tag, String value) {
        this.tag = tag;
        this.value = value;
    }

    public String getTag() {
        return this.tag;
    }

    public String getValue() {
        return value;
    }

    public static Map<String, String> toMap(CommonAlertTag... alertTags) {
        Map<String, String> map = new HashMap<>();
        for (CommonAlertTag tag : alertTags) {
            map.put(tag.getTag(), tag.getValue());
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Merges a {@code Map<String, String>} of {@code CommonAlertTag} with any number of other {@code CommonAlertTag}s.
     *
     * @param tagMap the {@code Map<String, String>} of {@code CommonAlertTag}s to be merged with.
     * @param alertTags the {@code CommonAlertTag}s to be added.
     * @return a {@code Map<String, String> of the unified collection of CommonAlertTags
     * @since 1.10.0
     */
    public static Map<String, String> mergeTags(
            Map<String, String> tagMap, CommonAlertTag... alertTags) {
        Map<String, String> map = new HashMap<>();
        map.putAll(tagMap);
        for (CommonAlertTag tag : alertTags) {
            map.put(tag.getTag(), tag.getValue());
        }
        return map;
    }
}
