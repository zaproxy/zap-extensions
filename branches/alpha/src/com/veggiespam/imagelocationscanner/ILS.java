package com.veggiespam.imagelocationscanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
//import java.io.FileOutputStream;

import org.apache.sanselan.ImageReadException;
import org.apache.sanselan.Sanselan;
import org.apache.sanselan.common.IImageMetadata;
import org.apache.sanselan.formats.jpeg.JpegImageMetadata;
import org.apache.sanselan.formats.tiff.TiffImageMetadata;

/**
 * Image Location Scanner main static class.  Passively scans a data stream containing a jpeg and reports if the 
 * data contains embedded Exif GPS location.  This is designed to be a plug-in for both ZAP and Burp proxies.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 0.1
 * @see http://www.veggiespam.com/ils/
 */
public class ILS {

	/** A bunch of static strings that are used by both ZAP and Burp plug-ins. */
    public static final String pluginName = "Image Location Scanner";
    public static final String pluginVersion = "0.1";
    public static final String alertTitle = "Image Contains Embedded Location Information";
    public static final String alertDetailPrefix = "This image contains embedded location information: ";
    public static final String alertBackground 
    	= "The image was found to contain embedded location information, such as GPS coordinates.  "
    	+ "Depending on the context of the image in the website, "
    	+ "this information may expose private details of the users of a site.  For example, a site that allows "
    	+ "users to upload profile pictures taken in the home may expose the home's address.  ";
    public static final String remediationBackground 
    	= "Before allowing images to be stored on the server and/or transmitted to the browser, strip out the "
    	+ "embedded location information from image.  This could mean removing all Exif data or just the GPS "
    	+ "component.";
    public static final String remediationDetail = null;
    public static final String referenceURL = "Place URL to Whitepaper here."; 
    public static final String pluginAuthor = "Jay Ball (veggiespam)"; 

   
	private static final String EmptyString = "";
	
	public ILS() {
		// blank constructor
		super();
	}
	
	/** Scans the input Jpeg meta data for GPS info.
	 * 
	 * @param jpegMetadata - previously scanned and alloc'd jpeg meta data
	 * @return String containing the Location data or an empty String indicating no GPS data found.
	 * @throws ImageReadException
	 */
	private static String scanJpeg(JpegImageMetadata jpegMetadata) throws ImageReadException {
		String ret = EmptyString;
		TiffImageMetadata exifMetadata = jpegMetadata.getExif();
		if (null != exifMetadata) {
			final TiffImageMetadata.GPSInfo gpsInfo = exifMetadata.getGPS();
			if (null != gpsInfo) {
				double longitude = gpsInfo.getLongitudeAsDegreesEast();
				double latitude = gpsInfo.getLatitudeAsDegreesNorth();
				if ((longitude != 0.0) && (latitude != 0.0) ) {
					// gpsInfo toString contains nulls for some reason.
					ret = gpsInfo.toString().replaceAll("\0",EmptyString);
				}
			}
		}
		return ret;
	}

    
	/** Tests a data blob for Location or GPS information and returns the 
	 * information as a string.  Otherwise, it will return an empty string.
	 * 
	 * @param data is a byte array that is an image file to test, such as entire jpeg file.
	 * @return String containing the Location data or an empty String indicating no GPS data found.
	 */
    public static String scanForLocationInImage(byte[] data)   {
    	String ret = EmptyString;
    	
    	/*  // Debugging code getting the data from Burp/ZAP/newproxy into ILS, ugh.
    	try{
       		FileOutputStream o = new FileOutputStream(new File("/tmp/output.jpg"));
			o.write(data);
			o.close();
    	} catch (IOException e) {
    		return new String("IOException Exception " + e.toString());
    	}
    	//return new String("Scanning " + data.length + "\n\n"  );
    	*/
 
    	try {
	        IImageMetadata md = Sanselan.getMetadata(data);
	        if (md instanceof JpegImageMetadata) {
	        	JpegImageMetadata jpim = (JpegImageMetadata) md;
                ret = scanJpeg( jpim );
	        }
	        // TODO : tests for png, tiff that call the proper decoders
    	} catch (ImageReadException e) {
    		// exception, must not be an image, so just ignore
    		// DEBUG: return new String("Image Read Exception " + e.toString());
    	} catch (IOException e) {
    		// huh? wtf...  unknown error, ignore
    		// DEBUG: return new String("IOException Exception " + e.toString());
    	}
    	return ret; 
    }


    
    public static void main(String[] args) throws Exception {
    	if (args.length == 0){
    		System.out.println("Java Image Location Scanner");
    		System.out.println("Usage: java ILS.class file1.jpg file2.png file3.txt [...]");
    		return;
    	}
    	for (String s: args) {
            try {
				System.out.print("Processing " + s + " : ");

				File f = new File(s);
				FileInputStream fis = new FileInputStream(f);
				long size = f.length();
				byte[] data = new byte[(int) size];
				fis.read(data);
				fis.close();
				
				String res = scanForLocationInImage(data);
				System.out.println(res);
        	} catch (IOException e) {
        		System.out.println(e.getMessage());
			} catch (Exception e) {
				e.printStackTrace();
			}
    	}
    }
}
