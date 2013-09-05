package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Set;

public class SAMLConfiguration {

    private static final String SAML_CONF_FILE = "zap_saml_conf.xml";
    private static SAMLConfiguration configuration = new SAMLConfiguration();

    private boolean initialized;
    private SAMLConfigData configData;

    protected static Logger log = Logger.getLogger(SAMLConfiguration.class);

    public static SAMLConfiguration getConfigurations(){
        return configuration;
    }

    /**
     * Initialize the attributes and configurations
     * @throws org.zaproxy.zap.extension.saml.SAMLException
     */
    public void initialize() throws SAMLException {
        String confPath = Model.getSingleton().getOptionsParam(). getUserDirectory().getAbsolutePath()+ "/" +
                SAML_CONF_FILE;
        initialize(confPath);
    }

    public void initialize(String confPath) throws SAMLException {
        File confFile = new File(confPath);

        if(!confFile.exists()){
            File defaultConfFile = new File(SAMLConfiguration.class.getResource(SAML_CONF_FILE).getFile());
            if (defaultConfFile.exists()){
                throw new SAMLException("Configuration file not found");
            }

            //try to copy configuration to user directory
            try {
                Files.copy(defaultConfFile.toPath(),confFile.toPath());
            } catch (IOException e) {
                throw new SAMLException("SAML Configuration file can't be modified, Will lose changes at exit");
            }
            confFile = defaultConfFile;
        }

        //load the configuration
        configData = (SAMLConfigData) loadXMLObject(SAMLConfigData.class,confFile);
        initialized = true;
    }

    public Set<Attribute> getAvailableAttributes() {
        return configData.getAvailableAttributes();
    }

    public Set<Attribute> getAutoChangeAttributes(){
        return configData.getAutoChangeValues();
    }

    public boolean getAutoChangeEnabled(){
        return configData.isAutoChangerEnabled();
    }

    public void setAutochangeEnabled(boolean value){
        configData.setAutoChangerEnabled(value);
    }

    public boolean getXSWEnabled(){
        return configData.isXswEnabled();
    }

    public void setXSWEnabled(boolean value){
        configData.setXswEnabled(value);
    }

    public boolean saveConfiguration(){
        try {
            JAXBContext context = JAXBContext.newInstance(SAMLConfigData.class);
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            String confPath = Model.getSingleton().getOptionsParam(). getUserDirectory().getAbsolutePath()+ "/" +
                    SAML_CONF_FILE;
            marshaller.marshal(configData,new File(confPath));
            return true;
        } catch (JAXBException e) {
            log.error("Saving configuration failed");
        }
        return false;
    }

    /**
     * Unmarshall the XML file and extract the object using JAXB
     * @param clazz class of the object
     * @param file xml file
     * @return unmarshalled object
     * @throws org.zaproxy.zap.extension.saml.SAMLException
     */
    private Object loadXMLObject(Class clazz, File file) throws SAMLException {
        try {
            JAXBContext context = JAXBContext.newInstance(clazz);
            Unmarshaller unmarshaller = context.createUnmarshaller();
            return unmarshaller.unmarshal(file);
        } catch (JAXBException e) {
            throw new SAMLException("XML loading failed",e);
        }
    }
}
