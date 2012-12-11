package org.zaproxy.zap.extension.usernameenumerationscan;

/**
 * Hirschberg.java
 * This class provides the implementation of Hirschberg's algorithm
 * that solves the Longest Common Subsequence (LCS) problem. This
 * implementation is using Hirschber's algorithb B and algorithm C.
 * 
 * @see http://code.google.com/p/algorithm800/source/browse/trunk/src/Hirschberg.java
 *
 * @author Valentinos Georgiades
 * @author Minh Nguyen
 *
 */
public class Hirshberg {
       
        /**
         * Generic constructor
         *
         */
        public Hirshberg() {
               
        }
       
        /**
         * Algorithm B as described by Hirschberg
         *
         * @param m
         * @param n
         * @param a
         * @param b
         * @return
         */
        public int[] algB(int m, int n, String a, String b) {
               
                // Step 1
                int[][] k = new int[2][n+1];
                for( int j=0; j<=n; j++) {
                        k[1][j] = 0;
                }
               
                // Step 2
                for(int i=1; i<=m; i++) {
                        // Step 3
                        for(int j=0; j<=n; j++) {
                                k[0][j] = k[1][j];
                        }
                       
                        // Step 4
                        for(int j=1; j<=n; j++) {
                                if(a.charAt(i-1) == b.charAt(j-1)) {
                                        k[1][j] = k[0][j-1] + 1;
                                }else{
                                        k[1][j] = max(k[1][j-1], k[0][j]);
                                }
                        }
                }
               
                //Step 5
                return k[1];
               
        }
       
        /**
         * This method returns the maximum number between two numbers.
         *
         * @param x
         * @param y
         * @return
         */
        public int max(int x, int y) {
                if(x>y) {
                        return x;
                }else{
                        return y;
                }
        }
       
        /**
         * Algorithm C as described by Hirschberg
         *
         * @param m
         * @param n
         * @param a
         * @param b
         * @return
         */
        public String algC(int m, int n, String a, String b) {
                int i=0;
                int j=0;
                String c = "";
               
                // Step 1
                if( n==0 ) {
                        c = "";
                } else if( m==1 ) {
                        c = "";
                        for( j=0; j<n; j++ ) {
                                if( a.charAt(0)==b.charAt(j) ) {
                                        c= ""+a.charAt(0);
                                        break;
                                }
                        }
                       
                // Step 2
                } else {
                        i= (int) Math.floor(((double)m)/2);
                       
                        // Step 3
                        int[] l1 = algB(i, n, a.substring(0,i), b);
                        int[] l2 = algB(m-i, n, reverseString(a.substring(i)), reverseString(b));
                       
                        // Step 4
                        int k = findK(l1, l2, n);
                       
                        // Step 5
                        String c1 = algC(i, k, a.substring(0, i), b.substring(0, k));
                        String c2 = algC(m-i, n-k, a.substring(i), b.substring(k));
                       
                        c = c1+c2;
                }
               
                return c; // The LCS
        }
       
       
        /**
         * This method takes a string as input reverses it and
         * returns the result
         *
         * @param in
         * @return
         */
        public String reverseString(String in) {
                String out = "";
               
                for(int i=in.length()-1; i>=0; i--) {
                        out = out+in.charAt(i);
                }
               
                return out;
        }
       
       
        /**
         * This method finds the index of the maximum sum of L1 and L2,
         * as described by Hirschberg
         *
         * @param l1
         * @param l2
         * @param n
         * @return
         */
        public int findK(int[] l1, int[] l2, int n) {
                int m = 0;
                int k = 0;
               
                for(int j=0; j<=n; j++) {      
                        if(m < (l1[j]+l2[n-j])) {
                                m = l1[j]+l2[n-j];
                                k = j;
                        }
                }
               
                return k;
        }
       
       
        /**
         * The main method for the algorithm
         *
         * @param args
         */
        public static void main(String[] args) {
                if(args.length != 2) {
                        System.err.println("Usage: Enter two strings X and Y");
                }else{
                        String x = args[0];
                        String y = args[1];
                        Hirshberg alg = new Hirshberg();
                        System.out.println("LCS: " + alg.algC(x.length(), y.length(), x, y)); //computes & prints out the result
                }
        }
        
        /**
         * convenience method to get the LCS of two Strings
         * @param a 
         * @param b
         * @return
         */
        public String lcs (String a, String b) {
        	return algC(a.length(), b.length(), a, b);
        }

}
