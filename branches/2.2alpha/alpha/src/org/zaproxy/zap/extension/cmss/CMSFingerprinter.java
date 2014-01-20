package org.zaproxy.zap.extension.cmss;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;


public class CMSFingerprinter {
	
	
	/**
	 *  Use BlindElephant DB to fingerprint webapp
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * 
	 */
	/*
	public static void FingerprintFileBE(URL url) throws IOException, NoSuchAlgorithmException{
		
		try {
		
			SAXBuilder builder = new SAXBuilder();
			Document doc = builder.build(new File("joomla.xml"));
			Element racine = doc.getRootElement();
			System.out.println(racine.getChildren().size());
			for (int i=0;i<racine.getChildren().size();i++){
				System.out.println(i);
				Element file = (Element)racine.getChildren().get(i);
				String path = file.getAttributeValue("path");
				URL filePath = new URL(url.toString()+path);
				int len = url.toString().length();
				String urlF = url.toString().substring(0, len-1);
				System.out.println("path == "+urlF+path);
				URLConnection con = filePath.openConnection();
				if (con.getContentLength()!= -1){
					String chksum = checkUrlContentChecksoms(filePath);
					System.out.println(chksum);
					for (int j=0;j<file.getChildren().size();j++){
						Element hashNode = (Element) file.getChildren().get(j);
						String hash = hashNode.getAttributeValue("md5");
						System.out.println(hash);
						if (hash.compareTo(chksum)==0){
							for(int k= 0 ;k<hashNode.getChildren().size();k++){
								Element versionNode = (Element)hashNode.getChildren().get(k);
								String version= versionNode.getValue();
								System.out.println("		version=="+version);
							}
							break; //<----
						}
					}
				}
				//else System.out.println("daznot");
			}
			
		} 
		catch (JDOMException e) {
			e.printStackTrace();	
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		
	}*/
	
	
	
	

}
