/*
 * Created on 06/02/2005
 *
 * JRandTest package
 *
 * Copyright (c) 2005, Zur Aougav, aougav@hotmail.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list 
 * of conditions and the following disclaimer. 
 * 
 * Redistributions in binary form must reproduce the above copyright notice, this 
 * list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution. 
 * 
 * Neither the name of the JRandTest nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without specific 
 * prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.fasteasytrade.JRandTest.Utils;

/**
 * original source from www1.fpl.fs.fed.us/Derf.np.java 
 * <p>
 * This class contains a Java translation of FORTRAN
 * routines written by W. Fullerton of LANL to calculate the
 * double precision error function and the double
 * precision complementary error function.
 * <p>
 * @version .5 --- February 21, 2002
 *
 * @author Zur Aougav
 */


public class Derf extends Object {


/**
*
*This method calculates the double precision error function.
*It is a Java translation of the FORTRAN
*routine derf written by W. Fullerton of LANL.  The FORTRAN
*version is part of the SLATEC library of numerical analysis
*routines.<p>
*Steve Verrill translated the FORTRAN code (updated 6/18/92)
*into Java.  This translation was performed on February 21, 2002.
*
*@param   x
*
*@version .5 --- February 21, 2002
*
*/


   public static double derf(double x) {

/*

Here is a copy of the documentation in the FORTRAN code:

	  DOUBLE PRECISION FUNCTION DERF (X)
C***BEGIN PROLOGUE  DERF
C***PURPOSE  Compute the error function.
C***LIBRARY   SLATEC (FNLIB)
C***CATEGORY  C8A, L5A1E
C***TYPE      DOUBLE PRECISION (ERF-S, DERF-D)
C***KEYWORDS  ERF, ERROR FUNCTION, FNLIB, SPECIAL FUNCTIONS
C***AUTHOR  Fullerton, W., (LANL)
C***DESCRIPTION
C
C DERF(X) calculates the double precision error function for double
C precision argument X.
C
C Series for ERF        on the interval  0.          to  1.00000E+00
C                                        with weighted error   1.28E-32
C                                         log weighted error  31.89
C                               significant figures required  31.05
C                                    decimal places required  32.55
C
C***REFERENCES  (NONE)
C***ROUTINES CALLED  D1MACH, DCSEVL, DERFC, INITDS
C***REVISION HISTORY  (YYMMDD)
C   770701  DATE WRITTEN
C   890531  Changed all specific intrinsics to generic.  (WRB)
C   890531  REVISION DATE from Version 3.2
C   891214  Prologue converted to Version 4.0 format.  (BAB)
C   900727  Added EXTERNAL statement.  (WRB)
C   920618  Removed space from variable name.  (RWC, WRB)
C***END PROLOGUE  DERF

*/

	  final double erfcs[] = {0.0,
	  -.49046121234691808039984544033376e-1,
	  -.14226120510371364237824741899631e+0,
	  +.10035582187599795575754676712933e-1,
	  -.57687646997674847650827025509167e-3,
	  +.27419931252196061034422160791471e-4,
	  -.11043175507344507604135381295905e-5,
	  +.38488755420345036949961311498174e-7,
	  -.11808582533875466969631751801581e-8,
	  +.32334215826050909646402930953354e-10,
	  -.79910159470045487581607374708595e-12,
	  +.17990725113961455611967245486634e-13,
	  -.37186354878186926382316828209493e-15,
	  +.71035990037142529711689908394666e-17,
	  -.12612455119155225832495424853333e-18,
	  +.20916406941769294369170500266666e-20,
	  -.32539731029314072982364160000000e-22,
	  +.47668672097976748332373333333333e-24,
	  -.65980120782851343155199999999999e-26,
	  +.86550114699637626197333333333333e-28,
	  -.10788925177498064213333333333333e-29,
	  +.12811883993017002666666666666666e-31};

	  final double sqrtpi = 1.77245385090551602729816748334115e0;

// SLATEC's d1mach(3) for IEEE 754 arithmetic should be 
// 2^{-53} = 1.11e-16.

	  final double d1mach3 = 1.11e-16;

// eta0 = .1*d1mach(3)

	  final double eta0 = 1.11e-17;

	  double y,ans;

	  double xbig,sqeps;

	  int nterf;


	  nterf = Derf.initds(erfcs,21,eta0);

	  xbig = Math.sqrt(-Math.log(sqrtpi*d1mach3));
	  sqeps = Math.sqrt(2.0*d1mach3);

	  y = Math.abs(x);

	  if (y <= 1.0) {

// ERF(X) = 1.0 - ERFC(X)  FOR  -1.0 .LE. X .LE. 1.0

		 if (y <= sqeps) {

			ans = 2.0*x*x/sqrtpi;

		 } else {

			ans = x*(1.0 + Derf.dcsevl(2.0*x*x - 1.0,erfcs,nterf));

		 }

		 return ans;

	  }

// 20

// ERF(X) = 1.0 - ERFC(X) FOR ABS(X) .GT. 1.0

	  if (y <= xbig) {

		 ans = Derf.sign(1.0 - Derf.derfc(y),x);

	  } else {

		 ans = Derf.sign(1.0,x);

	  }

	  return ans;

   }





/**
*
*This method calculates the double precision 
*complementary error function.
*It is a Java translation of the FORTRAN
*routine derfc written by W. Fullerton of LANL.  The FORTRAN
*version is part of the SLATEC library of numerical analysis
*routines.<p>
*Steve Verrill translated the FORTRAN code (updated 6/18/92)
*into Java.  This translation was performed on February 22, 2002.
*
*@param   x
*
*@version .5 --- February 22, 2002
*
*/


   public static double derfc(double x) {

/*

Here is a copy of the documentation in the FORTRAN code:


	  DOUBLE PRECISION FUNCTION DERFC (X)
C***BEGIN PROLOGUE  DERFC
C***PURPOSE  Compute the complementary error function.
C***LIBRARY   SLATEC (FNLIB)
C***CATEGORY  C8A, L5A1E
C***TYPE      DOUBLE PRECISION (ERFC-S, DERFC-D)
C***KEYWORDS  COMPLEMENTARY ERROR FUNCTION, ERFC, FNLIB,
C             SPECIAL FUNCTIONS
C***AUTHOR  Fullerton, W., (LANL)
C***DESCRIPTION
C
C DERFC(X) calculates the double precision complementary error function
C for double precision argument X.
C
C Series for ERF        on the interval  0.          to  1.00000E+00
C                                        with weighted Error   1.28E-32
C                                         log weighted Error  31.89
C                               significant figures required  31.05
C                                    decimal places required  32.55
C
C Series for ERC2       on the interval  2.50000E-01 to  1.00000E+00
C                                        with weighted Error   2.67E-32
C                                         log weighted Error  31.57
C                               significant figures required  30.31
C                                    decimal places required  32.42
C
C Series for ERFC       on the interval  0.          to  2.50000E-01
C                                        with weighted error   1.53E-31
C                                         log weighted error  30.82
C                               significant figures required  29.47
C                                    decimal places required  31.70
C
C***REFERENCES  (NONE)
C***ROUTINES CALLED  D1MACH, DCSEVL, INITDS, XERMSG
C***REVISION HISTORY  (YYMMDD)
C   770701  DATE WRITTEN
C   890531  Changed all specific intrinsics to generic.  (WRB)
C   890531  REVISION DATE from Version 3.2
C   891214  Prologue converted to Version 4.0 format.  (BAB)
C   900315  CALLs to XERROR changed to CALLs to XERMSG.  (THJ)
C   920618  Removed space from variable names.  (RWC, WRB)
C***END PROLOGUE  DERFC


*/

	  final double erfcs[] = {0.0,
	  -.49046121234691808039984544033376e-1,
	  -.14226120510371364237824741899631e+0,
	  +.10035582187599795575754676712933e-1,
	  -.57687646997674847650827025509167e-3,
	  +.27419931252196061034422160791471e-4,
	  -.11043175507344507604135381295905e-5,
	  +.38488755420345036949961311498174e-7,
	  -.11808582533875466969631751801581e-8,
	  +.32334215826050909646402930953354e-10,
	  -.79910159470045487581607374708595e-12,
	  +.17990725113961455611967245486634e-13,
	  -.37186354878186926382316828209493e-15,
	  +.71035990037142529711689908394666e-17,
	  -.12612455119155225832495424853333e-18,
	  +.20916406941769294369170500266666e-20,
	  -.32539731029314072982364160000000e-22,
	  +.47668672097976748332373333333333e-24,
	  -.65980120782851343155199999999999e-26,
	  +.86550114699637626197333333333333e-28,
	  -.10788925177498064213333333333333e-29,
	  +.12811883993017002666666666666666e-31};

	  final double erc2cs[] = {0.0,
	  -.6960134660230950112739150826197e-1,
	  -.4110133936262089348982212084666e-1,
	  +.3914495866689626881561143705244e-2,
	  -.4906395650548979161280935450774e-3,
	  +.7157479001377036380760894141825e-4,
	  -.1153071634131232833808232847912e-4,
	  +.1994670590201997635052314867709e-5,
	  -.3642666471599222873936118430711e-6,
	  +.6944372610005012589931277214633e-7,
	  -.1371220902104366019534605141210e-7,
	  +.2788389661007137131963860348087e-8,
	  -.5814164724331161551864791050316e-9,
	  +.1238920491752753181180168817950e-9,
	  -.2690639145306743432390424937889e-10,
	  +.5942614350847910982444709683840e-11,
	  -.1332386735758119579287754420570e-11,
	  +.3028046806177132017173697243304e-12,
	  -.6966648814941032588795867588954e-13,
	  +.1620854541053922969812893227628e-13,
	  -.3809934465250491999876913057729e-14,
	  +.9040487815978831149368971012975e-15,
	  -.2164006195089607347809812047003e-15,
	  +.5222102233995854984607980244172e-16,
	  -.1269729602364555336372415527780e-16,
	  +.3109145504276197583836227412951e-17,
	  -.7663762920320385524009566714811e-18,
	  +.1900819251362745202536929733290e-18,
	  -.4742207279069039545225655999965e-19,
	  +.1189649200076528382880683078451e-19,
	  -.3000035590325780256845271313066e-20,
	  +.7602993453043246173019385277098e-21,
	  -.1935909447606872881569811049130e-21,
	  +.4951399124773337881000042386773e-22,
	  -.1271807481336371879608621989888e-22,
	  +.3280049600469513043315841652053e-23,
	  -.8492320176822896568924792422399e-24,
	  +.2206917892807560223519879987199e-24,
	  -.5755617245696528498312819507199e-25,
	  +.1506191533639234250354144051199e-25,
	  -.3954502959018796953104285695999e-26,
	  +.1041529704151500979984645051733e-26,
	  -.2751487795278765079450178901333e-27,
	  +.7290058205497557408997703680000e-28,
	  -.1936939645915947804077501098666e-28,
	  +.5160357112051487298370054826666e-29,
	  -.1378419322193094099389644800000e-29,
	  +.3691326793107069042251093333333e-30,
	  -.9909389590624365420653226666666e-31,
	  +.2666491705195388413323946666666e-31};

	  final double erfccs[] = {0.0,
	  +.715179310202924774503697709496e-1,
	  -.265324343376067157558893386681e-1,
	  +.171115397792085588332699194606e-2,
	  -.163751663458517884163746404749e-3,
	  +.198712935005520364995974806758e-4,
	  -.284371241276655508750175183152e-5,
	  +.460616130896313036969379968464e-6,
	  -.822775302587920842057766536366e-7,
	  +.159214187277090112989358340826e-7,
	  -.329507136225284321486631665072e-8,
	  +.722343976040055546581261153890e-9,
	  -.166485581339872959344695966886e-9,
	  +.401039258823766482077671768814e-10,
	  -.100481621442573113272170176283e-10,
	  +.260827591330033380859341009439e-11,
	  -.699111056040402486557697812476e-12,
	  +.192949233326170708624205749803e-12,
	  -.547013118875433106490125085271e-13,
	  +.158966330976269744839084032762e-13,
	  -.472689398019755483920369584290e-14,
	  +.143587337678498478672873997840e-14,
	  -.444951056181735839417250062829e-15,
	  +.140481088476823343737305537466e-15,
	  -.451381838776421089625963281623e-16,
	  +.147452154104513307787018713262e-16,
	  -.489262140694577615436841552532e-17,
	  +.164761214141064673895301522827e-17,
	  -.562681717632940809299928521323e-18,
	  +.194744338223207851429197867821e-18,
	  -.682630564294842072956664144723e-19,
	  +.242198888729864924018301125438e-19,
	  -.869341413350307042563800861857e-20,
	  +.315518034622808557122363401262e-20,
	  -.115737232404960874261239486742e-20,
	  +.428894716160565394623737097442e-21,
	  -.160503074205761685005737770964e-21,
	  +.606329875745380264495069923027e-22,
	  -.231140425169795849098840801367e-22,
	  +.888877854066188552554702955697e-23,
	  -.344726057665137652230718495566e-23,
	  +.134786546020696506827582774181e-23,
	  -.531179407112502173645873201807e-24,
	  +.210934105861978316828954734537e-24,
	  -.843836558792378911598133256738e-25,
	  +.339998252494520890627359576337e-25,
	  -.137945238807324209002238377110e-25,
	  +.563449031183325261513392634811e-26,
	  -.231649043447706544823427752700e-26,
	  +.958446284460181015263158381226e-27,
	  -.399072288033010972624224850193e-27,
	  +.167212922594447736017228709669e-27,
	  -.704599152276601385638803782587e-28,
	  +.297976840286420635412357989444e-28,
	  -.126252246646061929722422632994e-28,
	  +.539543870454248793985299653154e-29,
	  -.238099288253145918675346190062e-29,
	  +.109905283010276157359726683750e-29,
	  -.486771374164496572732518677435e-30,
	  +.152587726411035756763200828211e-30};

	  final double sqrtpi = 1.77245385090551602729816748334115e0;


// SLATEC's d1mach(3) for IEEE 754 arithmetic should be 
// 2^{-53} = 1.11e-16.

	  final double d1mach3 = 1.11e-16;

// eta0 = .1*d1mach(3)

	  final double eta0 = 1.11e-17;

	  double ans,y;

	  double sqeps,xsml,txmax,xmax;

	  int nterf,nterfc,nterc2;


	  nterf = Derf.initds(erfcs,21,eta0);
	  nterfc = Derf.initds(erfccs,59,eta0);
	  nterc2 = Derf.initds(erc2cs,49,eta0);

	  sqeps = Math.sqrt(2.0*d1mach3);

	  xsml = -Math.sqrt(-Math.log(sqrtpi*d1mach3));

// For IEEE 754 arithmetic d1mach(1) = 2^{-1022}
// log(d1mach(1)) = -1022

	  txmax = Math.sqrt(-(Math.log(sqrtpi) - 1022));

	  xmax = txmax - 0.5*Math.log(txmax)/txmax - 0.01;


	  if (x <= xsml) {

// ERFC(X) = 1.0 - ERF(X)  FOR  X .LT. XSML

		 ans = 2.0;

		 return ans;

	  }

	  if (x > xmax) {

//		   System.out.print("\n\nx is so big that derfc underflows" +
//		   "\n\n");

		 ans = 0.0;

		 return ans;

	  }

	  y = Math.abs(x);

	  if (y <= 1.0) {

// ERFC(X) = 1.0 - ERF(X)  FOR ABS(X) .LE. 1.0

		 if (y < sqeps) {

			ans = 1.0 - 2.0*x/sqrtpi;

		 } else {

			ans = 1.0 - x*(1.0 + Derf.dcsevl(2.0*x*x - 1.0,erfcs,nterf));

		 }

		 return ans;

	  }

// ERFC(X) = 1.0 - ERF(X)  FOR  1.0 .LT. ABS(X) .LE. XMAX

	  y = y*y;

	  if (y <= 4.0) {

		 ans = (Math.exp(-y)/Math.abs(x))*(0.5 + 
			   Derf.dcsevl((8.0/y - 5.0)/3.0,erc2cs,nterc2));

	  } else {

		 ans = (Math.exp(-y)/Math.abs(x))*(0.5 + 
			   Derf.dcsevl(8.0/y - 1.0,erfccs,nterfc));

	  }

	  if (x < 0.0) ans = 2.0 - ans;

	  return ans;

   }






/**
*
*This method evaluates the n-term Chebyshev series cs at x.
*It is a Java translation of the FORTRAN
*routine dcsevl written by W. Fullerton of LANL.  The FORTRAN
*version is part of the SLATEC library of numerical analysis
*routines.<p>
*Steve Verrill translated the FORTRAN code (updated 5/1/92)
*into Java.  This translation was performed on February 22, 2002.
*
*@param   x    Value at which the series is to be evaluated
*@param   cs   Array of n terms of a Chebyshev series.  In evaluating
*              cs, only half the first coefficient is summed.
*@param   n    Number of terms in array cs (excludes the term
*              in the 0th spot)
*
*@version .5 --- February 22, 2002
*
*/


   public static double dcsevl(double x, double cs[], int n) {

/*

Here is a copy of the documentation in the FORTRAN code:

	  DOUBLE PRECISION FUNCTION DCSEVL (X, CS, N)
C***BEGIN PROLOGUE  DCSEVL
C***PURPOSE  Evaluate a Chebyshev series.
C***LIBRARY   SLATEC (FNLIB)
C***CATEGORY  C3A2
C***TYPE      DOUBLE PRECISION (CSEVL-S, DCSEVL-D)
C***KEYWORDS  CHEBYSHEV SERIES, FNLIB, SPECIAL FUNCTIONS
C***AUTHOR  Fullerton, W., (LANL)
C***DESCRIPTION
C
C  Evaluate the N-term Chebyshev series CS at X.  Adapted from
C  a method presented in the paper by Broucke referenced below.
C
C       Input Arguments --
C  X    value at which the series is to be evaluated.
C  CS   array of N terms of a Chebyshev series.  In evaluating
C       CS, only half the first coefficient is summed.
C  N    number of terms in array CS.
C
C***REFERENCES  R. Broucke, Ten subroutines for the manipulation of
C                 Chebyshev series, Algorithm 446, Communications of
C                 the A.C.M. 16, (1973) pp. 254-256.
C               L. Fox and I. B. Parker, Chebyshev Polynomials in
C                 Numerical Analysis, Oxford University Press, 1968,
C                 page 56.
C***ROUTINES CALLED  D1MACH, XERMSG
C***REVISION HISTORY  (YYMMDD)
C   770401  DATE WRITTEN
C   890831  Modified array declarations.  (WRB)
C   890831  REVISION DATE from Version 3.2
C   891214  Prologue converted to Version 4.0 format.  (BAB)
C   900315  CALLs to XERROR changed to CALLs to XERMSG.  (THJ)
C   900329  Prologued revised extensively and code rewritten to allow
C           X to be slightly outside interval (-1,+1).  (WRB)
C   920501  Reformatted the REFERENCES section.  (WRB)
C***END PROLOGUE  DCSEVL

*/

	  double b0,b1,b2,twox,ans,onepl;

	  int i,ni;

// SLATEC's d1mach(4) for IEEE 754 arithmetic should be 
// 2 x 2^{-53} = 2.22e-16.

	  final double d1mach4 = 2.22e-16;


	  onepl = 1.0 + d1mach4;

	  if (n < 1) {

		 System.out.print("\n\nERROR: The number of terms for dcsevl" +
		 " was less than 1.\n\n");

		  System.exit(0);

	  }

	  if (n > 1000) {

		 System.out.print("\n\nERROR: The number of terms for dcsevl" +
		 " was greater than 1000.\n\n");

		  System.exit(0);

	  }

	  if (Math.abs(x) > onepl) {

		 System.out.print("\n\nERROR: The x for dcsevl" +
		 " was outside the interval (-1,1).\n\n");

		  System.exit(0);

	  }

// We must initialize b2.
// Java doesn't know that the for loop will go
// (it doesn't know that we have excluded [above]
// the case in which n < 1)
// so it complains that b2 might not have been initialized
// when we use it below the for loop

	  b2 = 0.0;

	  b1 = 0.0;
	  b0 = 0.0;
	  twox = 2.0*x;

	  for (i = 1; i <= n; i++) {

		 b2 = b1;

		 b1 = b0;

		 ni = n + 1 - i;

		 b0 = twox*b1 - b2 + cs[ni];

	  }

	  ans = 0.5*(b0 - b2);

	  return ans;

   }







/**
*
*This method determines the number of terms needed
*in an orthogonal polynomial series so that it meets a specified
*accuracy.
*It is a Java translation of the FORTRAN
*routine initds written by W. Fullerton of LANL.  The FORTRAN
*version is part of the SLATEC library of numerical analysis
*routines.<p>
*Steve Verrill translated the FORTRAN code (updated 3/15/90)
*into Java.  This translation was performed on February 22, 2002.
*
*@param   os    Double precision array of nos coefficients in an
*               orthogonal series
*@param   nos   Number of coefficients in os
*@param   eta   Scalar containing the
*               requested accuracy of the series
*
*@version .5 --- February 22, 2002
*
*/


   public static int initds(double os[], int nos, double eta) {

/*

Here is a copy of the documentation in the FORTRAN code:

	  FUNCTION INITDS (OS, NOS, ETA)
C***BEGIN PROLOGUE  INITDS
C***PURPOSE  Determine the number of terms needed in an orthogonal
C            polynomial series so that it meets a specified accuracy.
C***LIBRARY   SLATEC (FNLIB)
C***CATEGORY  C3A2
C***TYPE      DOUBLE PRECISION (INITS-S, INITDS-D)
C***KEYWORDS  CHEBYSHEV, FNLIB, INITIALIZE, ORTHOGONAL POLYNOMIAL,
C             ORTHOGONAL SERIES, SPECIAL FUNCTIONS
C***AUTHOR  Fullerton, W., (LANL)
C***DESCRIPTION
C
C  Initialize the orthogonal series, represented by the array OS, so
C  that INITDS is the number of terms needed to insure the error is no
C  larger than ETA.  Ordinarily, ETA will be chosen to be one-tenth
C  machine precision.
C
C             Input Arguments --
C   OS     double precision array of NOS coefficients in an orthogonal
C          series.
C   NOS    number of coefficients in OS.
C   ETA    single precision scalar containing requested accuracy of
C          series.
C
C***REFERENCES  (NONE)
C***ROUTINES CALLED  XERMSG
C***REVISION HISTORY  (YYMMDD)
C   770601  DATE WRITTEN
C   890531  Changed all specific intrinsics to generic.  (WRB)
C   890831  Modified array declarations.  (WRB)
C   891115  Modified error message.  (WRB)
C   891115  REVISION DATE from Version 3.2
C   891214  Prologue converted to Version 4.0 format.  (BAB)
C   900315  CALLs to XERROR changed to CALLs to XERMSG.  (THJ)
C***END PROLOGUE  INITDS

*/

	  double err,ans;

	  int ii,i;



	  if (nos < 1) {

		 System.out.print("\n\nERROR: The number of coefficients for initds" +
		 " was less than 1.\n\n");

		  System.exit(0);

	  }

// We must initialize i.
// Java doesn't know that the for loop will go
// (it doesn't know that we have excluded [above]
// the case in which nos < 1)
// so it complains that i might not have been initialized
// when we use it below the for loop

	  i = nos;

	  err = 0.0;

	  for (ii = 1; ii <= nos; ii++) {

		 i = nos + 1 - ii;

		 err += Math.abs(os[i]);

		 if (err > eta) break;

	  }

	  if (i == nos) {

		 System.out.print("\n\nThe Chebyshev series is too short for the"
		 + " specified accuracy.\n\n");

	  }

	  return i;

   }


/**
*
*<p>
*This method implements the FORTRAN sign (not sin) function.
*See the code for details.
*
*Created by Steve Verrill, March 1997.
*
*@param  a   a
*@param  b   b
*
*/

   public static double sign (double a, double b) {

	  if (b < 0.0) {

		 return -Math.abs(a);

	  } else {

		 return Math.abs(a);      

	  }

   }



}
