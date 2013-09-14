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



public class CMSSUtils {
	
	/**
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static InputStream getFileFromUrl(URL url) throws IOException{
		
		InputStream is = null;
		try{
			is= url.openStream();
			File file = new File(url.getPath());
			//System.out.println("filename = "+file.getName());
			FileOutputStream out = new FileOutputStream(file.getName());
		}
		catch(Exception e){
			//e.printStackTrace();
		}
		
		/**
		 * some stuff to do here with 'out'
		 */
	
		return is;
	}
	/**
	 * 
	 * @param file
	 * @return
	 */
	public static String checkSumApacheCommons(InputStream is){
        String checksum = null;
        try {  
            checksum = DigestUtils.md5Hex(is);
        } catch (IOException e) {
            //logger.log(Level.SEVERE, null, ex);
        	e.printStackTrace();
        }
        return checksum;
    }
	/**
	 * 
	 * @param url
	 * @return
	 * @throws IOException
	 */
	public static String checkUrlContentChecksoms(URL url) throws IOException{
		String chksum = checkSumApacheCommons(getFileFromUrl(url));
		//System.out.println(chksum);
		return chksum;
	}
	
	
	// TODO make many tests for this function 
	public static String checksum(byte[] octets) throws UnsupportedEncodingException, NoSuchAlgorithmException{
		final MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		messageDigest.reset();
		messageDigest.update(octets);
		final byte[] resultByte = messageDigest.digest();
		return new String(Hex.encodeHex(resultByte));
	}
}
