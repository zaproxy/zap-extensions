package org.zaproxy.zap.extension.cmss;

import java.net.URL;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;

public class FastFingerprinter {
	
	
	// based on ODZscanner 
	
		/**
		 * I think that should be modular too
		 * @param url
		 * @return
		 */
		public static ArrayList<String> JoomlaFastFingerprint(URL url){
			// on se base sur ODZscanner
			WebPage wp = null;
			ArrayList<String> result = new ArrayList<String>();
			org.jsoup.nodes.Document doc = null;
			String dist = "";
			String htacc = "";
			String rdm ="";
			String doc2 = "";
			try {
				 wp = new WebPage(url);
				 doc = wp.getDocument();
			}
			catch(Exception e){
				e.printStackTrace();
			}
			try{
				doc2 = IOUtils.toString(CMSSUtils.getFileFromUrl(new URL(url.toString()+"/index.php?option=com_esi")),"UTF-8");
			}catch(Exception e){
			
			}
			try{
				
				rdm = IOUtils.toString(CMSSUtils.getFileFromUrl(new URL(url.toString()+"/README.txt")),"UTF-8");
			}catch(Exception e){
				
			}
			try{
				
				htacc = IOUtils.toString(CMSSUtils.getFileFromUrl(new URL(url.toString()+"/htaccess.txt")),"UTF-8");

			}catch(Exception e){
				
			}
				 
			try{
	
				dist = IOUtils.toString(CMSSUtils.getFileFromUrl(new URL(url.toString()+"/configuration.php-dist")),"UTF-8");

			}catch(Exception e){
			
			}
				 
			Pattern p , p2;
				p = Pattern.compile("<\\/html> <!-- \\d{1,30} -->");
				p2 = Pattern.compile("The page you are trying to access does not exist");
				try{
					Matcher m = p.matcher(doc.toString()), 
					 m2 = p2.matcher(doc2.toString());
					 
					if (m.find() || m2.find() 
						|| WebAppGuesser.checkIfExist(new URL(url.toString()+"/language/english.xml"))
						|| WebAppGuesser.checkIfExist(new URL(url.toString()+"/administrator/templates/joomla_admin/images/security.png")))
					result.add("1.0.x");
				}catch(Exception e){
					
				}
					 
				p = Pattern.compile(" Joomla! 1.5 - Open Source Content Management");
				p2 = Pattern.compile("404- Component not found");
				
				try{
					Matcher m = p.matcher(doc.toString());
					Matcher m2 = p2.matcher(doc2);
					if (m.find() || m2.find() 
						|| WebAppGuesser.checkIfExist(new URL(url.toString()+"/administrator/templates/khepri/images/j_login_lock.jpg"))
						|| WebAppGuesser.checkIfExist(new URL(url.toString()+"/administrator/templates/khepri/images/j_button1_next.png")))
						result.add("1.5.x");
				}catch(Exception e){
					
				}

				 p = Pattern.compile("package to version 3.0.x");
				 	
				 try{
					 Matcher m = p.matcher(rdm.toString());
				 	if (m.find() || WebAppGuesser.checkIfExist(new URL(url.toString()+
				   		"/administrator/templates/isis/img/glyphicons-halflings.png")))
				 		result.add("3.0.x");
				 }catch(Exception e){
					 
				 }
				 try{  	
				 if(searchByRegex("47 2005-09-15 02:55:27Z rhuk", htacc.toString()))
					 result.add("[1.0.0 - 1.0.2]");
				 }
				 catch(Exception e){
					 
				 }
				 try{ 	 
				 if(searchByRegex("423 2005-10-09 18:23:50Z stingrey", htacc.toString()))
					 result.add("1.0.3");
				 }catch(Exception e){
					  
				  }
				 try{ 	
				 if(searchByRegex("1005 2005-11-13 17:33:59Z stingrey", htacc.toString()))
					 result.add("[1.0.4 - 1.0.5]");
				 }catch(Exception e){
					  
				  }
				 try{ 
				 if(searchByRegex("1570 2005-12-29 05:53:33Z eddieajau", htacc.toString()))
					 result.add("[1.0.6 - 1.0.7]");
				 }catch(Exception e){
					 
				  }
				 try{
				 if(searchByRegex("2368 2006-02-14 17:40:02Z stingrey", htacc.toString()))
					 result.add("[1.0.8 - 1.0.9]");
				 }catch(Exception e){
					  
				  }
				 try{
				 if(searchByRegex("44085 2006-06-21 16:03:54Z stingrey7 2005-09-15 02:55:27Z rhuk", htacc.toString()))
					 result.add("1.0.10");
				 }catch(Exception e){
					 
				  }
				 try{
				 if(searchByRegex("4756 2006-08-25 16:07:11Z stingrey", htacc.toString()))
					 result.add("1.0.11");
				 }catch(Exception e){
					 
				  }
				 try{
				if(searchByRegex("5973 2006-12-11 01:26:33Z robs", htacc.toString()))
					result.add("1.0.12");
				 }catch(Exception e){
					 
				  }
				 try{
				if(searchByRegex("5975 2006-12-11 01:26:33Z robs", htacc.toString()))
					result.add("[1.0.13 - 1.0.15]");
				 }catch(Exception e){
					 
				  }
				 try{
				if(searchByRegex("47 2005-09-15 02:55:27Z rhuk", dist.toString()))
					result.add("1.0.0");
				 }catch(Exception e){
					  
				  }
				 try{
				if(searchByRegex("217 2005-09-21 15:15:58Z stingrey", dist.toString()))
					result.add("[1.0.1 - 1.0.2]");
				 }catch(Exception e){
					  
				  }
				 try{
				if(searchByRegex("506 2005-10-13 05:49:24Z stingrey", dist.toString()))
					result.add("[1.0.3 - 1.0.7]");
				 }catch(Exception e){
					  
				  }
				 try{  	 
				if(searchByRegex("2622 2006-02-26 04:16:09Z stingrey", dist.toString()))
					result.add("1.0.8");
				 }catch(Exception e){
					 
				  }
				 try{
				    if(searchByRegex("3754 2006-05-31 12:08:37Z stingrey", dist.toString()))
				    	result.add("[1.0.9 - 1.0.10]");
				 }catch(Exception e){
					  e.printStackTrace();
				  }
			return result;			
		}


		public static boolean searchByRegex(String regex, String str){
			Pattern p = Pattern.compile(regex);
			Matcher m = p.matcher(str);
			if (m.find()) return true;
			return false;
		}
		
		
		// this method is presented here :
		// http://www.antoine-cervoise.fr/2012/10/20/wordpress-version-checker-new-md5-list/?lang=fr
		public static ArrayList<String>  WordpressFastFingerprint(URL url){
			boolean exist = false;
			ArrayList<String> result = new ArrayList<String>();
			URL indicFileUrl = null;
			try{
				 exist = WebAppGuesser.checkIfExist(new URL(url.toString()+"/wp-includes/js/tinymce/tiny_mce.js"));
				 
			}catch(Exception e){
				e.printStackTrace();
			}
			if(exist){
				try{
					indicFileUrl = new URL(url.toString()+"/wp-includes/js/tinymce/tiny_mce.js");
					String myString = IOUtils.toString(CMSSUtils.getFileFromUrl(indicFileUrl), "UTF-8");
					String chksum = CMSSUtils.checksum(myString.getBytes());
					System.out.println(chksum);
					if(chksum.compareTo("a306a72ce0f250e5f67132dc6bcb2ccb")==0)
						for(String str:"2.0; 2.0.1; 2.0.4; 2.0.5; 2.0.6; 2.0.7; 2.0.8; 2.0.9; 2.0.10; 2.0.11".split(";")){
							result.add(str);
						}
					if(chksum.compareTo("4f04728cb4631a553c4266c14b9846aa")==0)
						for(String str:"2.1; 2.1.1; 2.1.2; 2.1.3".split(";")){
							result.add(str);
						}
									
					if(chksum.compareTo("25e1e78d5b0c221e98e14c6e8c62084f")==0)
					    for(String str:"2.2; 2.2.1; 2.2.2; 2.2.3".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("83c83d0f0a71bd57c320d93e59991c53")==0)
									
					 for(String str:"2.3; 2.3.1; 2.3.2; 2.3.3".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("7293453cf0ff5a9a4cfe8cebd5b5a71a")==0)							
						    result.add("2.5");

					if(chksum.compareTo("a3d05665b236944c590493e20860bcdb")==0)
						    result.add("2.5.1");
								    
					if(chksum.compareTo("61740709537bd19fb6e03b7e11eb8812")==0)
									
					 for(String str:"2.6; 2.6.1; 2.6.2; 2.6.3; 2.6.5".split(";")){
						    result.add(str);
								    }
					if(chksum.compareTo("e6bbc53a727f3af003af272fd229b0b2")==0)
									
					 for(String str:"2.7; 2.7.1".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("56c606da29ea9b8f8d823eeab8038ee8")==0)
									
					 for(String str:"2.8; 2.8.1; 2.8.2; 2.8.3; 2.8.4; 2.8.5; 2.8.6".split(";")){
						    result.add(str);
			     	    }
					if(chksum.compareTo("128e75ed19d49a94a771586bf83265ec")==0)
						
					 for(String str:"2.9; 2.9.1; 2.9.2; 3.0; 3.0.1; 3.0.2; 3.0.3; 3.0.4; 3.0.5; 3.0.6".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("82ac611e3da57fa3e9973c37491486ee")==0)
						result.add("3.1");
								    
					if(chksum.compareTo("e52dfe5056683d653536324fee39ca08")==0)
									
					 for(String str:"3.1.1; 3.1.2; 3.1.3; 3.1.4".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("a57c0d7464527bc07b34d675d4bf0159")==0)
									
					 for(String str:"3.2; 3.2.1".split(";")){
						    result.add(str);
					    }
					if(chksum.compareTo("9754385dabfc67c8b6d49ad4acba25c3")==0)
									
					 for(String str:"3.3; 3.3.1; 3.3.2; 3.3.3".split(";")){
					    result.add(str);
				    }
					if(chksum.compareTo("7424043e0838819af942d2fc530e8469")==0)
									
					 for(String str:"3.4; 3.4.1; 3.4.2".split(";")){
					    result.add(str);
					    }
				     else System.out.println("lolz");
								
				}
				catch(Exception e){
					System.out.println("file not found");
				}
							
			}
			return result;
		}

	/**
	 * This method take the result of : wapalyzer and guessWebApp.fastguess
	 * , combine between them 
	 * @param targetUrl
	 * @param whatToFingerPrint
	 * @param POrAOption
	 * @return
	 * @throws Exception
	 */
	public static ArrayList<String> filterResults(URL targetUrl, ArrayList<String> whatToFingerPrint,int POrAOption) throws Exception{
		
		ArrayList<String> result = new ArrayList<String>();
		ArrayList<String> wapGessed = new ArrayList<String>();
		ArrayList<String> blindGuessed = new ArrayList<String>();
		if(POrAOption == 1 || POrAOption==3){
			wapGessed = Wappalyzer.analyse(targetUrl,whatToFingerPrint);
			for (String app : wapGessed){
				result.add(app);
			}
			if(POrAOption==3){
				blindGuessed = WebAppGuesser.guessApps(targetUrl);
				for (String app : blindGuessed){
					result.add(app);
				}
			}
		}else{
			blindGuessed = WebAppGuesser.guessApps(targetUrl);
			for (String app : blindGuessed){
				result.add(app);
			}	
		}
		
		
		System.out.println("fin");
		
		return result;
	}
	
	
}
