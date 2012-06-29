package org.zaproxy.zap.extension.tokengen;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasteasytrade.JRandTest.Algo.JavaRandom;
import com.fasteasytrade.JRandTest.IO.RandomStream;
import com.fasteasytrade.JRandTest.Tests.Base;
import com.fasteasytrade.JRandTest.Tests.MonteCarlo;

public class CmdLineTest {

	/*
	 * TODO: for first commit
	 * : i18n
	 *   TokenParam - sort out
	 *   Handle rnd ints, one way or another...
	 *   Problems if low number of token generated (2000)
	 * TODO: before release
	 *   Support url tokens
	 *   runs and longest run tests
	 *   2D spectoral tests / binary rank / complex stuff ...
	 *   Raise alert option?
	 *   show analysis dialog button?
	 * Done
	 * | change to table
	 * | help to details
	 * | prettify details - monospace font etc
	 * | Save, load
	 * | Issue: Cant run more than once!
	 * | Highlight tokens on select
	 * | Cancel
	 * | Support form tokens
	 * | Highlight errors
	 * | Report issues in checkCharacterTransitions !
	 * | Analysis progress bar
	 * | Tidy code
	 * | TokenParam - sort out
	 * Dont
	 * 
	 * TODO - find out ask where the MDEV calc comes from! (send email..)
	 *  
	 */

	public static Double calculateShannonEntropy(List<String> values) {
		  Map<String, Integer> map = new HashMap<String, Integer>();
		  // count the occurrences of each value
		  for (String sequence : values) {
		    if (!map.containsKey(sequence)) {
		      map.put(sequence, 0);
		    }
		    map.put(sequence, map.get(sequence) + 1);
		  }

		  // calculate the entropy
		  Double result = 0.0;
		  for (String sequence : map.keySet()) {
		    Double frequency = (double) map.get(sequence) / values.size();
		    result -= frequency * (Math.log(frequency) / Math.log(2));
		  }

		  return result;
	}


	public static void runTest(Base test, RandomStream rs) throws Exception {
		
		test.registerInput(rs);
		test.test(rs.getFilename());
		System.out.println("\n");
	}


	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		CharacterFrequencyMap cfm = new CharacterFrequencyMap();
		//cfm.load(new File("sbsb/rnd/SB_BigInt256.txt"));
		cfm.load(new File("sbsb/rnd/10000tokens.txt"));
		
		TokenRandomStream trs = new TokenRandomStream(cfm);
		trs.openInputStream();
		
		// OK Tests
		/*
		runTest (new Count16Bits(), trs);
		runTest (new Count1Bit(), trs);			// Diehard (all of the count bits?
		runTest (new Count2Bits(), trs);
		runTest (new Count3Bits(), trs);
		runTest (new Count4Bits(), trs);
		runTest (new Count8Bits(), trs);
		*/
		
		// Dont understand results
//		runTest (new BinaryRankTestFor6x8Matrices(), trs);			// Diehard 
//		runTest (new BinaryRankTestFor31x31Matrices(), trs);		// Diehard
//		runTest (new BinaryRankTestFor32x32Matrices(), trs);		// Diehard
//		runTest (new BirthdaySpacings(), trs);						// Diehard
		runTest (new MonteCarlo(), trs);
//		runTest (new OverlappingPairsSparseOccupancy(), trs);		// Diehard
//		runTest (new DNA(), trs);
//		runTest (new OverlappingQuadruplesSparseOccupancy(), trs);	// Diehard
//		runTest (new Squeeze(), trs);								// Diehard

		// Not OK Tests
		/*
		runTest (new CountThe1s(), trs);
		runTest (new CountThe1sSpecificBytes(), trs);
		runTest (new MinimumDistance(), trs);						// Diehard
		*/
		//runTest (new Overlapping20TuplesBitstream(), trs);
		//runTest (new Run(), trs);									// Diehard/NIST?
		/*
		*/

		
		runTest (new MonteCarlo(), new JavaRandom());

		// Still to test Tests...
		
/*
		Double entropy = calculateShannonEntropy(cfm.getTokens());
		System.out.println("Entropy is " + entropy);
		System.out.println("Max theoretical entropy is " + cfm.getMaxTheoreticalEntropy());
		*/
		//Date start = new Date();
		//cfm.hack();
		
		/* 
		cfm.checkCharacterUniformity();
		cfm.checkCharacterTransitions();
		 */
		
		//System.out.println("Took " + ((new Date()).getTime() - start.getTime()));
		

		//runTest (new BinaryRankTestFor6x8Matrices(), trs);
		//runTest (new BinaryRankTestFor6x8Matrices(), new AES());
/*		
		FileRandomStream frs = new FileRandomStream();
		frs.setFilename("/home/simon/paros/session/test/vuln/tokens10000");

		runTest (new Count1Bit(), frs);

		runTest (new Count1Bit(), trs);
*/
	}

}
