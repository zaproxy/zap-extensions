package org.zaproxy.zap.extension.cmss;

import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

import org.apache.commons.codec.DecoderException;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;

public class WebAppGuesser {
	

	/**
	 *************** TODO method checkIfExist ---> to support : url+/blabla/+lien
	 */

	private static URL urlToGuess ;
	
	/*
	 * Path to the fast guessing used file
	 * the fast guessing consists on use a number of detector files (those of BlinElephant)
	 * to check the name of the webapp, and not the version 
	 */
	private static String fastAppGuessBD = "resources/fastGuess/fastGuess.xml"; 
	
	
	
	public static void setUrlToGuess(URL url){
		urlToGuess = url;
	}
		
		
	/**
	* this function return a list of possible version according to the presence or not 
	* of indicator files 
	* 
	* TODO : implement analyze of HTTP response and compare with 404 model file
	* 
	* 
	* @param urlToGuess
	* @return
	* @throws MalformedURLException
	* @throws IOException
	 * @throws NoSuchAlgorithmException 
	 * @throws DecoderException 
	*/
	public static ArrayList<String> guessApps(URL urlToGuess) throws MalformedURLException, IOException, NoSuchAlgorithmException, DecoderException{
			ArrayList<String> guessedApps = new ArrayList<String>();
			Document doc = getFastGuessBDD(fastAppGuessBD);  
			Element racine = doc.getRootElement();	
			for(int i=0;i<racine.getChildren().size();i++){
				Element app = (Element)racine.getChildren().get(i);
				String appName = app.getAttributeValue("name");
				//System.out.println(appName);
				for(int j=0;j<app.getChildren().size();j++){
					String indicFilePath = ((Element)app.getChildren().get(j)).getValue();
					//System.out.println(indicFilePath);
					if(checkIfExist(urlToGuess, indicFilePath)){
						
						// ici soit on retourne le resultat ou on passe au fingerprinting
						System.out.println(appName);
						
						// ********************************************
						
						// here we can change this to : pass urlToGuess 
						// to fingerprintFile as an argument or ...
						setUrlToGuess(urlToGuess);
						// TODO the following call must return a set of versions
						//fingerPrintFile(appName);
						guessedApps.add(appName.toLowerCase());
						break;
					}		
				}
			}
			return guessedApps;	
		}
		
	public static ArrayList<String> fingerPrintFile(String appName) throws MalformedURLException, IOException, NoSuchAlgorithmException, DecoderException{
		ArrayList<String> versions = new ArrayList<String>();
		boolean stop = false;
		Document doc = loadFingerPrintingDB((appName2dbPath(appName)));
		Element racine = doc.getRootElement();
		for(int i =0;i<racine.getChildren().size();i++){
			Element file = (Element)racine.getChildren().get(i);
			String path = file.getAttributeValue("path");
			if(checkIfExist(urlToGuess, path)){
				System.out.println("path that match = "+path);
				
				//-------------------------------------------------
				//TODO here i must introduce accuracy
				//options to specify accuracy fingerprinting level
				//--------------------------------------------------
				
				for (int j=0;j<file.getChildren().size();j++){
					Element hashNode = (Element) file.getChildren().get(j);
					String hash = hashNode.getAttributeValue("md5");
					/*String chksum = 
							CMSFingerprinter.checkUrlContentChecksoms(
									new URL(urlToGuess.toString()+path));*/
					/*String chksum = CMSFingerprinter.
							checksum(wp.getDocument()+urlToGuess.toString()+path);*/
				        
					    
					// We convert the url content and the file path into byte arrays, then
					// we concatenate them, then we calculate its checksum
					byte[] octets1 = new byte[0];
					CMSSUtils.getFileFromUrl(new URL(urlToGuess+path)).read(octets1);
					byte[] octets2 = path.getBytes(); // doit etre avant la boucle for
					byte[] c = new byte[octets1.length + octets2.length];
					System.arraycopy(octets1, 0, c, 0, octets1.length);
					System.arraycopy(octets2, 0, c, octets1.length, octets2.length);
					String chksum = CMSSUtils.checksum(c);
					
					System.out.println("hash = "+hash);
					System.out.println("chksum = "+chksum);
					if (hash.compareTo(chksum)==0){
						stop=true;
						System.out.println("hhhhhhhh");
						ArrayList<String> pathAssociatedVerions = new ArrayList<String>();
						for(int k= 0 ;k<hashNode.getChildren().size();k++){	
							Element versionNode = (Element)hashNode.getChildren().get(k);
							String version= versionNode.getValue();
							version = version.substring(0, 3);
							if(!pathAssociatedVerions.contains(version)){
								pathAssociatedVerions.add(version);
							}									
							System.out.println("		version=="+version);
						}
						for(String app:pathAssociatedVerions){
							versions.add(app);
						}	
						break; // parceque un fichier sur le net n'a pas deux hashes
					}			
				}
				if (stop) break; //  should analyze all files
			}
			else /*System.out.println("dont exist !!")*/;
		}
		HashMap<String,Integer> calculList = new HashMap<String,Integer>();
		ArrayList<String> finalResult = new ArrayList<String>();
		for(String version:versions){
			if(calculList.containsKey(version)){
				int nbr = calculList.get(version);
				calculList.remove(version);
				calculList.put(version, nbr+1);
			}
			else{
				calculList.put(version, 1);
			}
		}
		int max = 1 ;
		for(Entry<String, Integer> entry : calculList.entrySet()){
			int occ = entry.getValue();
			if(occ>max){
				max = occ;
				System.out.println(max);
			}	
		}
		for(Entry<String, Integer> entry : calculList.entrySet()){
			if(entry.getValue()==max) finalResult.add(entry.getKey());
		}
		return finalResult;
	}
	
	
	/**
	 * open the xml file of the given path and return a DOM document of this file
	 * @param dbPath:path to the db file 
	 * @return
	 */
	public static Document loadFingerPrintingDB(String dbPath){
		Document doc = null;
		try{
			SAXBuilder builder = new SAXBuilder();
			doc = builder.build(new File(dbPath));
		}
		catch (JDOMException e) {
			e.printStackTrace();	
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		return doc;
	}
	
	
	/**
	 * from an app name return the correspondent xml file 
	 * eg: appName = joomla => this function return : db/joomla/joomla.xml
	 * @param appName
	 * @return
	 */
	public static String appName2dbPath(String appName){
		/**
		 * here is defined a naming and locating convention for webapps DBs
		 */
		return "resources/CMSSdb/"+appName+"/"+appName+".xml";
	}
	
	
	/**
	 * TODO: extend it to check url+/blabla/+filepath, that extended call this not extended one
	 * like this : checkIfExist(url) with one argument
	 * 
	 * Answer if a given file exists in a given webapp
	 * @return true if the file exists, false else
	 * @param appUrl
	 * @param filePath
	 * @throws IOException 
	 * 
	 */
	public static boolean checkIfExist(URL appUrl, String filePath) throws IOException{
		URL completeUrl = new URL(appUrl.toString()+filePath);
		//System.out.println("-->"+completeUrl.toString());
		HttpURLConnection  con = (HttpURLConnection) completeUrl.openConnection();
		con.setRequestMethod("HEAD");
		//System.out.println(con.getResponseCode());
		if(con.getResponseCode() == HttpURLConnection.HTTP_OK){
			//System.out.println("yes");
			return true;
		}
		return false;
	}
	
	
	/**
	 * 
	 ***************** pending
	 * 
	 * 
	 * 
	 * Answer if a given url exists (server code 200)
	 * @return true if the file exists, false else
	 * @param appUrl
	 * @param filePath
	 * @throws IOException 
	 * 
	 */
	public static boolean checkIfExist(URL url) throws IOException{
		
		//System.out.println("-->"+completeUrl.toString());
		HttpURLConnection  con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("HEAD");
		//System.out.println(con.getResponseCode());
		int responseCode = -917 ;
		while(responseCode==-917){
			try{
				responseCode = con.getResponseCode();
			}
			catch(ConnectException e){
				System.out.println("Retrying to connect");
			}
		}
		if(responseCode == HttpURLConnection.HTTP_OK){
			//System.out.println("yes");
			return true;
		}
		return false;
	}
	
	
	/**
	 * open the file in bddPath (xml file) and return a DOM document of this file 
	 * 
	 * @param bddPath
	 * @return
	 */
	public static Document getFastGuessBDD (String bddPath){
		Document doc = null;
		try{
			SAXBuilder builder = new SAXBuilder();
			doc = builder.build(new File(bddPath));
		}
		catch (JDOMException e) {
			e.printStackTrace();	
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		return doc;
	}
}
