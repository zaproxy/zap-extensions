package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.*;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Set;

public class SAMLConfiguration implements AttributeListener {

    private static final String SAML_CONF_FILE = "zap_saml_conf.xml";
    private static final String SAML_CONF_FILE_PATH = Paths.get(Constant.getZapHome(), SAML_CONF_FILE).toString();
    private static SAMLConfiguration configuration = new SAMLConfiguration();

    private SAMLConfigData configData;

    protected final static Logger log = Logger.getLogger(SAMLConfiguration.class);

    /**
     * Get the singleton configurations object
     * @return
     */
    public static SAMLConfiguration getInstance() {
        return configuration;
    }

    /**
     * Initialize the attributes and configurations
     *
     * @throws SAMLException
     */
    public void initialize() throws SAMLException {
        initialize(SAML_CONF_FILE_PATH);
    }

    /**
     * Initialize the configuration using the config file at given path, if file is not available this will try to
     * load the default settings that are bundled with the extension and will be saved to user directory
     *
     * @param confPath Configuration file path
     * @throws SAMLException If both configuration file and default configuration files are not available
     */
    public void initialize(String confPath) throws SAMLException {
        File confFile = new File(confPath);

        if (!confFile.exists()) {
            URL confURL = getClass().getResource("resources/"+SAML_CONF_FILE);
            if (confURL ==null) {
                log.error("Configuration file not found ");
                throw new SAMLException("Configuration file not found");

            }
            //try to copy configuration to user directory
            try {
                confFile.createNewFile();
                BufferedReader reader = new BufferedReader(new InputStreamReader(confURL.openStream()));
                BufferedWriter writer = new BufferedWriter(new FileWriter(confFile));
                String line;
                while ((line=reader.readLine())!=null){
                    writer.write(line);
                    writer.newLine();
                }
                writer.flush();
                writer.close();
                reader.close();

            } catch (IOException e) {
                throw new SAMLException("SAML Configuration file "+confFile.getAbsolutePath()+" can't be modified");
            }
        }

        //load the configuration
        configData = (SAMLConfigData) loadXMLObject(SAMLConfigData.class, confFile);
    }

    /**
     * Get the set of all attributes that are defined in the extension
     *
     * @return
     */
    public Set<Attribute> getAvailableAttributes() {
        return configData.getAvailableAttributes();
    }

    /**
     * Get the set of attributes that need to be changed to the given values before the message is sent to the end
     * point
     *
     * @return set of attributes that will be changed within the message if present
     */
    public Set<Attribute> getAutoChangeAttributes() {
        return configData.getAutoChangeValues();
    }

    /**
     * Get whether the auto attribute value change at passive scanner is enabled
     *
     * @return <code>true</code> if enabled, <code>false</code> if disabled.
     */
    public boolean getAutoChangeEnabled() {
        return configData.isAutoChangerEnabled();
    }

    /**
     * Enable or disable automatic attribute value change at the passive scanner. If enabled the values of the
     * attributes will be changes as predefined, before the message is sent to the endpoint
     *
     * @param value <code>true</code> to enable auto change, <code>false</code> to disable it.
     */
    public void setAutochangeEnabled(boolean value) {
        configData.setAutoChangerEnabled(value);
    }

    /**
     * Whether the XSW (signature removal) is enabled.
     *
     * @return <code>true</code> if enabled, <code>false</code> if disabled
     * @see #setXSWEnabled(boolean)
     */
    public boolean getXSWEnabled() {
        return configData.isXswEnabled();
    }

    /**
     * Set true to remove signature of the messages (if present) to simulate signature exclusion attacks
     *
     * @param value <code>true</code> to remove signatures if present, <code>false</code> to keep unchanged.
     */
    public void setXSWEnabled(boolean value) {
        configData.setXswEnabled(value);
    }

    /**
     * Get whether the validation is enabled for attribute data types.
     *
     * @return <code>true</code> if validation is enabled, <code>false</code> if disabled
     * @see #setValidationEnabled(boolean)
     */
    public boolean isValidationEnabled() {
        return configData.isValidationEnabled();
    }

    /**
     * Get whether the validation is enabled for the attribute types. Enabling this will ensure invalid data types are
     * not set to the attributes. Disabling validation gives the user the ability to set whatever values he/she like,
     * inject new attributes which may be needed for some tests
     *
     * @param value <code>true</code> to enable validation, <code>false</code> to disable it.
     */
    public void setValidationEnabled(boolean value) {
        configData.setValidationEnabled(value);
    }

    /**
     * Save the configurations to the xml file
     *
     * @return <code>true</code> if save is success, <code>false</code> otherwise
     */
    public boolean saveConfiguration() {
        try {
            JAXBContext context = JAXBContext.newInstance(SAMLConfigData.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            marshaller.marshal(configData, new File(SAML_CONF_FILE_PATH));
            return true;
        } catch (JAXBException e) {
            log.error("Saving configuration failed");
        }
        return false;
    }

    /**
     * Unmarshall the XML file and extract the object using JAXB
     *
     * @param clazz class of the object
     * @param file  xml file
     * @return unmarshalled object
     * @throws SAMLException
     */
    private Object loadXMLObject(Class<?> clazz, File file) throws SAMLException {
        try {
            JAXBContext context = JAXBContext.newInstance(clazz);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return unmarshaller.unmarshal(file);
        } catch (JAXBException e) {
            throw new SAMLException("XML loading failed", e);
        }
    }

    @Override
    public void onAttributeAdd(Attribute a) {
        configData.getAvailableAttributes().add(a);
    }

    @Override
    public void onAttributeDelete(Attribute a) {
        Attribute attributeToDelete = null;
        for (Attribute attribute : configData.getAvailableAttributes()) {
            if (attribute.getName().equals(a.getName())) {
                attributeToDelete = attribute;
            }
        }
        configData.getAvailableAttributes().remove(attributeToDelete);
    }
}
