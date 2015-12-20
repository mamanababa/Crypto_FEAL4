package crypto;

import java.util.ArrayList;

public class LinFealK1 {
	// candidates of K1~ and K1
	static ArrayList<String> K1T = new ArrayList<String>();
	static ArrayList<String> K1 = new ArrayList<String>();
	static int[] countQ = new int[2];
	static int[] countE = new int[2];
	static int[] countF = new int[2];
	static int[] countG = new int[2];
	static int[] countH = new int[2];
	static int q = 0;// for K1~
	static int e = 0;// constant equation 1
	static int f = 0;// constant equation 2
	static int g = 0;// constant equation 3
	static int h = 0;// constant equation 4
	static String L0 = " ";// plain text left
	static String R0 = " ";// plain text right
	static String L4 = " ";// cipher text left
	static String R4 = " ";// cipher text right

	static ArrayList<String> attacK1T() {
		ArrayList<String> allK1T = LinFealK0.allK0T;
		int s15 = 0;
		int s5_13_21 = 0;
		int s15F = 0;

		// start time
		long t1 = System.currentTimeMillis();
		System.out.println("\nSTART");

		// calculate equation a in all K1~ and pairs
		System.out
				.println("Calculating equation Q in all K1~ , possible K1, and pairs");
		for (int k = 0; k < allK1T.size(); k++) {
			// counts times for a = 0 or 1
			countQ[0] = countQ[1] = 0;// initialize
			// 200 pairs
			for (int i = 0; i < LinFealK0.P.size(); i++) {
				// possible K0 found in last round
				for (int j = 0; j < LinFealK0.K0.size(); j++) {
					// split pairs to left and right part
					L0 = LinFealK0.P.get(i).substring(0, 32);
					R0 = LinFealK0.P.get(i).substring(32);
					L4 = LinFealK0.C.get(i).substring(0, 32);
					R4 = LinFealK0.C.get(i).substring(32);

					// S15(L0 R0) S5,13,21(F(L0 R0 K0)) S15(F(K1~ L0 F(L0 R0
					// K0)))
					s15 = LinFealK0.cal(L0.substring(15, 16))
							^ LinFealK0.cal(R0.substring(15, 16));

					// reverse every 8bits before pass to F function
					String BiToF = LinFealK0.reverse(LinFealK0.xOR(L0, R0,
							LinFealK0.K0.get(j)));
					// then pass to f function
					long fValue = LinFealK0.f(Long.parseLong(BiToF, 2));

					// result convert to binary
					String fString = Long.toBinaryString(fValue);
					// paddingg
					while (fString.length() < 32)
						fString = "0" + fString;
					// cut off first 32bits from negative long value
					while (fString.length() > 32)
						fString = fString.substring(32);

					// reverse every 8bits after F function
					fString = LinFealK0.reverse(fString);
					// take out the bit 5,13,21
					s5_13_21 = LinFealK0.cal(fString.substring(5, 6))
							^ LinFealK0.cal(fString.substring(13, 14))
							^ LinFealK0.cal(fString.substring(21, 22));

					// -------calculate S15(F(K1~ L0 F(L0 R0 K0)))
					// reverse every 8bits before pass to F function
					String BiToF2 = LinFealK0.reverse(LinFealK0.xOR(
							allK1T.get(k), L0, fString));
					// then pass to f function
					long fValue2 = LinFealK0.f(Long.parseLong(BiToF2, 2));

					// result convert to binary code
					String fString2 = Long.toBinaryString(fValue2);
					// paddingg
					while (fString2.length() < 32)
						fString2 = "0" + fString2;
					// cut off first 32bits from negative long value
					while (fString2.length() > 32)
						fString2 = fString2.substring(32);

					// reverse every 8bits after F function
					fString2 = LinFealK0.reverse(fString2);
					// take out bit 31
					s15F = LinFealK0.cal(fString2.substring(15, 16));

					q = s15 ^ s5_13_21 ^ s15F ^ 1;
					if (q == 0)
						countQ[0] += 1;
					else if (q == 1)
						countQ[1] += 1;

					if (j != 0 && countQ[0] > 1 && countQ[1] > 1)
						break;
				}
			}// end of pairs loop

			if (countQ[0] == 200 || countQ[1] == 200)
				// save K for candidate K0T
				K1T.add(allK1T.get(k));
		}// end of loop k
			// end time
		long t2 = System.currentTimeMillis();
		System.out.println("\nEND, time: " + (t2 - t1) + "ms");

		if (K1T.size() != 0) {
			System.out.print("Found " + K1T.size() + " K1~:\n");
			for (String s : K1T)
				System.out.println(s);
		} else
			System.out.println("Couldn't find K1~");
		return K1T;
	}// end of attacK0T method

	// after K1~, exhaustive 2 sides 2bytes allchoices in 200 pairs
	// expression
	static ArrayList<String> attacK1() {
		ArrayList<String> allK1 = new ArrayList<String>();
		System.out
				.println("\n----K1----\nGenerating 2^20 possible K1 depends on bits 0...7 , 8, 9, 16, 17, 24...32");
		String a0 = K1T.get(0).substring(8, 16);
		String a1 = K1T.get(0).substring(16, 24);
		String kk = "00000000000000000000000000000000";// 32bits
		String b0 = kk.substring(0, 8);// 0-7
		String b1 = kk.substring(8, 16);// 8-15
		String b2 = kk.substring(16, 24);// 16-23
		String b3 = kk.substring(24);// 24-31
		for (int k = 0; k < 65536; k++) {
			String k1 = Integer.toBinaryString(k);
			while (k1.length() < 16)
				k1 = "0" + k1;
			// replace 16bits of 0...7 , 24...32 in to 32bits KK
			b0 = k1.substring(0, 8);
			b3 = k1.substring(8);
			for (int i = 0; i < 16; i++) {
				String m = Integer.toBinaryString(i);
				while (m.length() < 4)
					m = "0" + m;
				a0 = m.substring(0, 2) + a0.substring(2);
				a1 = m.substring(2) + a1.substring(2);
				// b1= b0 ^ a0
				b1 = LinFealK0.xOR2(b0, a0);
				// b2= b3 ^ a1
				b2 = LinFealK0.xOR2(b3, a1);
				kk = b0 + b1 + b2 + b3;
				allK1.add(kk);
			}
		}
		// start time
		long t1 = System.currentTimeMillis();
		System.out.println("\nSTART\nAll K1: " + allK1.size());

		// calculate equation a in all K1 and pairs
		System.out.println("Calculating equations in all K1 and pairs");
		for (int k = 0; k < allK1.size(); k++) {
			// initialize counts times for each constant equation = 0 or 1
			countE[0] = countE[1] = countF[0] = countF[1] = countG[0] = countG[1] = countH[0] = countH[1] = 0;
			// 200 pairs
			for (int i = 0; i < LinFealK0.P.size(); i++) {
				// possible K0 found in last round
				for (int j = 0; j < LinFealK0.K0.size(); j++) {
					// split pairs to left and right part
					L0 = LinFealK0.P.get(i).substring(0, 32);
					R0 = LinFealK0.P.get(i).substring(32);
					L4 = LinFealK0.C.get(i).substring(0, 32);
					R4 = LinFealK0.C.get(i).substring(32);

					// calculate equation e
					// S31(L0+R0) + S31(F(K1+L0+F(L0 R0 K0)) +
					// S23,29(F(L0+R0+K0)) ^1
					int s31 = LinFealK0.cal(L0.substring(31))
							^ LinFealK0.cal(R0.substring(31));

					// the value to F function
					String biToF = LinFealK0.xOR(L0, R0, LinFealK0.K0.get(j));
					// reverse every 8bits before pass to F function
					long valueToF = Long.parseLong(LinFealK0.reverse(biToF), 2);

					// then pass to f function
					long fValue = LinFealK0.f(valueToF);

					// result convert to binary code
					String fString = Long.toBinaryString(fValue);
					// paddingg
					while (fString.length() < 32)
						fString = "0" + fString;

					// cut off first 32bits from negative long value
					while (fString.length() > 32)
						fString = fString.substring(32);

					// reverse every 8bits after F function
					fString = LinFealK0.reverse(fString);

					// take out the bit 23,29
					int s23_29 = LinFealK0.cal(fString.substring(23, 24))
							^ LinFealK0.cal(fString.substring(29, 30));

					// the value to F function
					String biToF2 = LinFealK0.xOR(allK1.get(k), L0, fString);
					// reverse every 8bits before pass to F function
					long valueToF2 = Long.parseLong(LinFealK0.reverse(biToF2),
							2);

					// then pass to f function
					// result convert to binary code
					String fString2 = Long.toBinaryString(LinFealK0
							.f(valueToF2));
					// paddingg
					while (fString2.length() < 32)
						fString2 = "0" + fString2;

					// cut off first 32bits from negative long value
					while (fString2.length() > 32)
						fString2 = fString2.substring(32);

					// reverse every 8bits after F function
					fString2 = LinFealK0.reverse(fString2);
					// take out the bit 31
					int s31F = LinFealK0.cal(fString2.substring(31));
					e = s31 ^ s23_29 ^ s31F ^ 1;
					if (e == 0)
						countE[0] += 1;
					else if (e == 1)
						countE[1] += 1;

					// calculate equation f
					// S23,31(L0+R0) + S23,31(F(K1+L0+F(L0 R0 K0)) +
					// S15,21(F(L0+R0+K0)) ^1
					int s23_31 = LinFealK0.cal(L0.substring(23, 24))
							^ LinFealK0.cal(R0.substring(23, 24))
							^ LinFealK0.cal(L0.substring(31))
							^ LinFealK0.cal(R0.substring(31));

					// take out the bit 15,21
					int s15_21 = LinFealK0.cal(fString.substring(15, 16))
							^ LinFealK0.cal(fString.substring(21, 22));

					// take out the bit 23,31
					int s23_31F = LinFealK0.cal(fString2.substring(23, 24))
							^ LinFealK0.cal(fString2.substring(31));
					f = s23_31 ^ s15_21 ^ s23_31F ^ 1;
					if (f == 0)
						countF[0] += 1;
					else if (f == 1)
						countF[1] += 1;

					// calculate equation g
					// S7(L0+R0) + S7(F(K1+L0+F(L0 R0 K0)) +
					// S5,15(F(L0+R0+K0)) ^1
					int s7 = LinFealK0.cal(L0.substring(7, 8))
							^ LinFealK0.cal(R0.substring(7, 8));

					// take out the bit 5,15
					int s5_15 = LinFealK0.cal(fString.substring(5, 6))
							^ LinFealK0.cal(fString.substring(15, 16));

					// take out the bit 7
					int s7F = LinFealK0.cal(fString2.substring(7, 8));
					g = s7 ^ s5_15 ^ s7F ^ 1;
					if (g == 0)
						countG[0] += 1;
					else if (g == 1)
						countG[1] += 1;

					// calculate equation h
					// S7,15,23,31(L0+R0) + S7,15,23,31(F(K1+L0+F(L0 R0 K0)) +
					// S13(F(L0+R0+K0)) ^1
					int s7_15_23_31 = LinFealK0.cal(L0.substring(7, 8))
							^ LinFealK0.cal(L0.substring(15, 16))
							^ LinFealK0.cal(L0.substring(23, 24))
							^ LinFealK0.cal(L0.substring(31))
							^ LinFealK0.cal(R0.substring(7, 8))
							^ LinFealK0.cal(R0.substring(15, 16))
							^ LinFealK0.cal(R0.substring(23, 24))
							^ LinFealK0.cal(R0.substring(31));

					// take out the bit 13
					int s13 = LinFealK0.cal(fString.substring(13, 14));

					// take out the bit 7,15,23,31
					int s7_15_23_31F = LinFealK0.cal(fString2.substring(7, 8))
							^ LinFealK0.cal(fString2.substring(15, 16))
							^ LinFealK0.cal(fString2.substring(23, 24))
							^ LinFealK0.cal(fString2.substring(31));
					h = s7_15_23_31 ^ s13 ^ s7_15_23_31F ^ 1;
					if (h == 0)
						countH[0] += 1;
					else if (h == 1)
						countH[1] += 1;

					if ((j != 0)
							&& ((countE[0] > 0 && countE[1] > 0)
									|| (countF[0] > 0 && countF[1] > 0)
									|| (countG[0] > 0 && countG[1] > 0) || (countH[0] > 0 && countH[1] > 0)))
						break;
				}
			}// end of pairs loop

			// if all equations are constant, save K for candidate K1
			if ((countE[0] == 200 || countE[1] == 200)
					&& (countF[0] == 200 || countF[1] == 200)
					&& (countG[0] == 200 || countG[1] == 200)
					&& (countH[0] == 200 || countH[1] == 200)) {
				K1.add(allK1.get(k));
			}
		}// end of loop k
			// end time
		long t2 = System.currentTimeMillis();
		System.out.println("\nEND, time: " + (t2 - t1) + "ms");

		if (K1.size() != 0) {
			System.out.println("Found " + K1.size() + " K1:");
			for (String s : K1)
				System.out.println(s + ", length:" + s.length() + ", "
						+ Long.toHexString(Long.parseLong(s, 2)));
		} else
			System.out.println("Couldn't find K1");
		return K1;
	}
}
