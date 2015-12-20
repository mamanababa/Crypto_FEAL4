package crypto;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class LinFealK0 {
	// all paintext and cipertext pairs
	static ArrayList<String> P = new ArrayList<String>();
	static ArrayList<String> C = new ArrayList<String>();
	// candidates of K0~ and K0
	static ArrayList<String> K0T = new ArrayList<String>();
	static ArrayList<String> K0 = new ArrayList<String>();

	static ArrayList<String> allK0T = new ArrayList<String>();

	static int[] countA = new int[2];
	static int[] countB = new int[2];
	static int[] countC = new int[2];
	static int[] countD = new int[2];
	static int a = 0;// constant equation 1
	static int b = 0;// constant equation 2
	static int c = 0;// constant equation 3
	static int d = 0;// constant equation 4
	static String L0 = " ";// plain text left
	static String R0 = " ";// plain text right
	static String L4 = " ";// cipher text left
	static String R4 = " ";// cipher text right

	// read all pairs, convert to 64bits binary string
	private static void readPairs() {
		ArrayList<String> pairs = new ArrayList<String>();
		BufferedReader br = null;
		System.out.println("Reading plaintext and ciphertext");
		try {

			String path = LinFealK0.class.getClassLoader().getResource("")
					.getPath()
					+ "known.txt";
			br = new BufferedReader(new FileReader(path));
			String line = null;
			while ((line = br.readLine()) != null) {
				if (line.length() > 1)
					pairs.add(line);
				// System.out.println(line);
			}
			// convert plaintext and ciphertext to binary string
			for (int i = 0; i < pairs.size(); i++) {
				String[] ss = null;
				ss = pairs.get(i).split("=");
				if (i % 2 == 0)
					P.add(toBinary(ss[1].trim()));
				else
					C.add(toBinary(ss[1].trim()));
			}
			// int a = 0;
			// for (String pp : p) {
			// System.out.println("P" + a + ": " + pp + ", " + pp.length());
			// a++;
			// }
			// System.out.println("----------------------");
			// int b = 0;
			// for (String cc : c) {
			// System.out.println("C" + b + ": " + cc + ", " + cc.length());
			// b++;
			// }
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}// end of readPairs method

	// exhaustive K0～ (middle 2bytes) all choices in 200 pairs
	// equation A =
	// S5,13(L0+R0+L4) + S21(L0+R0+L4) + S15(L0+R4+L4) + S15(F(L0+R0+K0~))
	private static ArrayList<String> attacK0T() {
		int s5_13 = 0;
		int s21 = 0;
		int s15 = 0;
		int s15F = 0;

		// check
		// K0~ : 8...15 , 16...23
		// all 2^12 possible K0~ depends
		// on 12bits of K0~ 10..15,18..23
		System.out
				.println("----K0~----\nGenerating 2^12 possible K0~ depends on bits 10..15,18..23");

		String kk = "00000000000000000000000000000000";// 32bits
		String kk1 = kk.substring(0, 10);// 0-9
		String kk2 = kk.substring(10, 16);// 10-15
		String kk3 = kk.substring(16, 18);// 16-17
		String kk4 = kk.substring(18, 24);// 18-23
		String kk5 = kk.substring(24);// 24-32
		for (int k = 0; k < 4096; k++) {
			String k0 = Integer.toBinaryString(k);// 0-4095 all possible K0~
													// depends on 12bits convert
													// to binary
			while (k0.length() < 12)
				k0 = "0" + k0;
			// replace 12bits of K0~ 10..15, 18..23 in to 32bits KK
			kk2 = k0.substring(0, 6);
			kk4 = k0.substring(6);

			kk = kk1 + kk2 + kk3 + kk4 + kk5;
			// System.out.println(k + ", bits of 10..15,18..23: " + k0);
			// System.out.println("put them in to K0~: " + kk);
			allK0T.add(kk);
		}

		// start time
		long t1 = System.currentTimeMillis();
		System.out.println("\nSTART");

		// calculate equation a in all K0~ and pairs
		System.out.println("Calculating equation A in all K0~ and pairs");
		for (int k = 0; k < allK0T.size(); k++) {
			// counts times for constant equation a = 0 or 1
			countA[0] = countA[1] = 0;// initialize

			// 200 pairs
			for (int i = 0; i < P.size(); i++) {
				// check
				// split pairs to left and right part
				L0 = P.get(i).substring(0, 32);
				R0 = P.get(i).substring(32);
				L4 = C.get(i).substring(0, 32);
				R4 = C.get(i).substring(32);

				// System.out.println(i);
				// System.out.println(L0 + "\n" + R0 + "\n" + L4 + "\n" + R4);

				// calculate equation
				// S5,13(L0+R0+L4) + S21(L0+R0+L4) + S15(L0+R4+L4) +
				// S15(F(L0+R0+K0~))
				s5_13 = cal(L0.substring(5, 6)) ^ cal(L0.substring(13, 14))
						^ cal(R0.substring(5, 6)) ^ cal(R0.substring(13, 14))
						^ cal(L4.substring(5, 6)) ^ cal(L4.substring(13, 14));

				s21 = cal(L0.substring(21, 22)) ^ cal(R0.substring(21, 22))
						^ cal(L4.substring(21, 22));

				s15 = cal(L0.substring(15, 16)) ^ cal(L4.substring(15, 16))
						^ cal(R4.substring(15, 16));

				// System.out.println("pair "+ i + ": " + s5_13 + ", " + s21
				// +", " +s15);

				// xor L0, R0 K0~ first
				String biToF = xOR(L0, R0, allK0T.get(k));
				// if ((k < 5) && (i == 0)) {
				// System.out.println("value[" + k + "]" + "in pair " + i);
				// System.out.println("binary to F : " + biToF + ", "
				// + biToF.length());
				// }

				// reverse every 8bits before pass to F function
				String newBiToF = reverse(biToF);
				long valueToF = Long.parseLong(newBiToF, 2);
				// System.out.println("long value to F  : " + valueToF);

				// String hex = Long.toHexString(valueToF);
				// while (hex.length() < 8)
				// hex = "0" + hex;
				// System.out.println("hex to F : " + hex + ", " + hex.length()
				// + "\n");

				// then pass to f function
				long fValue = f(valueToF);
				// System.out.println("F result: " + fValue);

				// result convert to binary code
				String fString = Long.toBinaryString(fValue);
				// paddingg
				while (fString.length() < 32)
					fString = "0" + fString;
				// cut off first 32bits from negative long value
				while (fString.length() > 32)
					fString = fString.substring(32);

				// reverse every 8bits after F function
				fString = reverse(fString);
				// if ((k < 5) && (i == 0)) {
				// System.out.println("K0~[" + k + "]" + "in pair " + i);
				// System.out.println(fValue + " -> " + fString + ", "
				// + fString.length() + "\n");
				// }

				// take out the bit 15
				s15F = cal(fString.substring(15, 16));
				a = s5_13 ^ s21 ^ s15 ^ s15F;
				if (a == 0)
					countA[0] += 1;
				else if (a == 1)
					countA[1] += 1;
			}// end of pairs loop

			// System.out.println("count0 = " + count[0] + ", count1 = "
			// + count[1]);
			if (countA[0] == 200 || countA[1] == 200) {
				// save K for candidate K0T
				// System.out.print("equation = " + a);
				K0T.add(allK0T.get(k));
			}
		}// end of loop k
			// end time
		long t2 = System.currentTimeMillis();
		System.out.println("\nEND, time: " + (t2 - t1) + "ms");

		if (K0T.size() != 0) {
			System.out.print("Found K0~:");
			for (String s : K0T)
				System.out.println(s + ", length:" + s.length());
		} else
			System.out.println("Couldn't find K0~");
		return K0T;
	}// end of attacK0T method

	// after K0~, exhaustive 2 sides 2bytes all choices in 200 pairs
	private static ArrayList<String> attacK0() {
		ArrayList<String> allK0 = new ArrayList<String>();
		System.out
				.println("\n----K0----\nGenerating 2^20 possible K0 depends on bits 0...7 , 8, 9, 16, 17, 24...32");
		String a0 = K0T.get(0).substring(8, 16);
		String a1 = K0T.get(0).substring(16, 24);
		String kk = "00000000000000000000000000000000";// 32bits
		String b0 = kk.substring(0, 8);// 0-7
		String b1 = kk.substring(8, 16);// 8-15
		String b2 = kk.substring(16, 24);// 16-23
		String b3 = kk.substring(24);// 24-31
		for (int k = 0; k < 65536; k++) {
			String k0 = Integer.toBinaryString(k);
			while (k0.length() < 16)
				k0 = "0" + k0;
			// replace 16bits of 0...7 , 24...32 in to 32bits KK
			b0 = k0.substring(0, 8);
			b3 = k0.substring(8);
			for (int i = 0; i < 16; i++) {

				String m = Integer.toBinaryString(i);
				while (m.length() < 4)
					m = "0" + m;
				a0 = m.substring(0, 2) + a0.substring(2);
				a1 = m.substring(2) + a1.substring(2);
				// b1= b0 ^ a0
				b1 = xOR2(b0, a0);
				// b2= b3 ^ a1
				b2 = xOR2(b3, a1);

				kk = b0 + b1 + b2 + b3;
				// System.out.println("b0:" + b0 + "\nb1:" + b1 + "\nb2:" + b2
				// + "\nb3:" + b3 + "\n");
				allK0.add(kk);
			}
		}

		// start time
		long t1 = System.currentTimeMillis();
		System.out.println("\nSTART\nAll K0: " + allK0.size());

		// calculate equation a in all K0 and pairs
		System.out.println("Calculating equations in all K0 and pairs");
		for (int k = 0; k < allK0.size(); k++) {
			// initialize counts times for each constant equation = 0 or 1
			countA[0] = countA[1] = countB[0] = countB[1] = countC[0] = countC[1] = countD[0] = countD[1] = 0;

			// 200 pairs
			for (int i = 0; i < P.size(); i++) {
				// check
				// split pairs to left and right part
				L0 = P.get(i).substring(0, 32);
				R0 = P.get(i).substring(32);
				L4 = C.get(i).substring(0, 32);
				R4 = C.get(i).substring(32);

				// calculate equation a
				// S23,29(L0+R0+L4) + S31(L0+L4+R4) + S31(F(L0+R0+K0))
				int s23_29 = cal(L0.substring(23, 24))
						^ cal(L0.substring(29, 30)) ^ cal(R0.substring(23, 24))
						^ cal(R0.substring(29, 30)) ^ cal(L4.substring(23, 24))
						^ cal(L4.substring(29, 30));

				int s31 = cal(L0.substring(31)) ^ cal(L4.substring(31))
						^ cal(R4.substring(31));

				// the value to F function
				String biToF = xOR(L0, R0, allK0.get(k));
				// reverse every 8bits before pass to F function
				String newBiToF = reverse(biToF);
				long valueToF = Long.parseLong(newBiToF, 2);

				// then pass to f function
				long fValue = f(valueToF);
				// System.out.println("F result: " + fValue);

				// result convert to binary code
				String fString = Long.toBinaryString(fValue);
				// paddingg
				while (fString.length() < 32)
					fString = "0" + fString;

				// cut off first 32bits from negative long value
				while (fString.length() > 32)
					fString = fString.substring(32);

				// reverse every 8bits after F function
				fString = reverse(fString);

				// take out the bit 31
				int s31F = cal(fString.substring(31));
				a = s23_29 ^ s31 ^ s31F;
				if (a == 0)
					countA[0] += 1;
				else if (a == 1)
					countA[1] += 1;

				// equation b
				// S13(L0+R0+L4) + S7,15,23,31(L0+L4+R4) +
				// S7,15,23,31(F(L0+R0+K0))
				int s13 = cal(L0.substring(13, 14)) ^ cal(R0.substring(13, 14))
						^ cal(L4.substring(13, 14));
				int s7_15_23_31 = cal(L0.substring(7, 8))
						^ cal(L0.substring(15, 16)) ^ cal(L0.substring(23, 24))
						^ cal(L0.substring(31)) ^ cal(R4.substring(7, 8))
						^ cal(R4.substring(15, 16)) ^ cal(R4.substring(23, 24))
						^ cal(R4.substring(31)) ^ cal(L4.substring(7, 8))
						^ cal(L4.substring(15, 16)) ^ cal(L4.substring(23, 24))
						^ cal(L4.substring(31));
				// take out the bit 7,15,23,31
				int s7_15_23_31F = cal(fString.substring(7, 8))
						^ cal(fString.substring(15, 16))
						^ cal(fString.substring(23, 24))
						^ cal(fString.substring(31));
				b = s13 ^ s7_15_23_31 ^ s7_15_23_31F;
				if (b == 0)
					countB[0] += 1;
				else if (b == 1)
					countB[1] += 1;

				// equation c
				// S5,15(L0+R0+L4) + S7(L0+L4+R4) + S7(F(L0+R0+K0))
				int s5_15 = cal(L0.substring(5, 6)) ^ cal(L0.substring(15, 16))
						^ cal(R0.substring(5, 6)) ^ cal(R0.substring(15, 16))
						^ cal(L4.substring(5, 6)) ^ cal(L4.substring(15, 16));
				int s7 = cal(L0.substring(7, 8)) ^ cal(L4.substring(7, 8))
						^ cal(R4.substring(7, 8));

				// take out the bit 7
				int s7F = cal(fString.substring(7, 8));
				c = s5_15 ^ s7 ^ s7F;
				if (c == 0)
					countC[0] += 1;
				else if (c == 1)
					countC[1] += 1;

				// equation d
				// S15,21(L0+R0+L4) + S23,31(L0+L4+R4) + S23,31(F(L0+R0+K0))
				int s15_21 = cal(L0.substring(15, 16))
						^ cal(L0.substring(21, 22)) ^ cal(R0.substring(15, 16))
						^ cal(R0.substring(21, 22)) ^ cal(L4.substring(15, 16))
						^ cal(L4.substring(21, 22));

				int s23_31 = cal(L0.substring(23, 24)) ^ cal(L0.substring(31))
						^ cal(L4.substring(23, 24)) ^ cal(L4.substring(31))
						^ cal(R4.substring(23, 24)) ^ cal(R4.substring(31));
				// take out the bit 23,31
				int s23_31F = cal(fString.substring(23, 24))
						^ cal(fString.substring(31));
				d = s15_21 ^ s23_31 ^ s23_31F;
				if (d == 0)
					countD[0] += 1;
				else if (d == 1)
					countD[1] += 1;

				if ((i != 0)
						&& ((countA[0] > 0 && countA[1] > 0)
								|| (countB[0] > 0 && countB[1] > 0)
								|| (countC[0] > 0 && countC[1] > 0) || (countD[0] > 0 && countD[1] > 0)))
					// i = 200;
					break;
			}// end of pairs loop

			// if all equations are constant, save K for candidate K0
			if ((countA[0] == 200 || countA[1] == 200)
					&& (countB[0] == 200 || countB[1] == 200)
					&& (countC[0] == 200 || countC[1] == 200)
					&& (countD[0] == 200 || countD[1] == 200)) {
				K0.add(allK0.get(k));
			}
		}// end of loop k
			// end time
		long t2 = System.currentTimeMillis();
		System.out.println("\nEND, time: " + (t2 - t1) + "ms");

		if (K0.size() != 0) {
			System.out.println("Found " + K0.size() + " K0:");
			for (String s : K0)
				System.out.println(s + ", length:" + s.length() + ", "
						+ Long.toHexString(Long.parseLong(s, 2)));
		} else
			System.out.println("Couldn't find K0");
		return K0;
	}// end of attacK0 method

	static String reverse(String fString) {
		// reverse
		String new1 = null;
		String new2 = null;
		String new3 = null;
		String new4 = null;
		String newS = null;
		new1 = fString.substring(24);
		new2 = fString.substring(16, 24);
		new3 = fString.substring(8, 16);
		new4 = fString.substring(0, 8);
		newS = new1 + new2 + new3 + new4;
		// System.out.println("before:       " + fString);
		// System.out.println("after:        " + newS + "\n");
		return newS;
	}

	static String toBinary(String hex) {
		String bi = "";
		String frag = "";
		int iHex;
		hex = hex.trim();
		for (int i = 0; i < hex.length(); i++) {
			iHex = Integer.parseInt("" + hex.charAt(i), 16);
			frag = Integer.toBinaryString(iHex);
			while (frag.length() < 4)
				frag = "0" + frag;
			bi += frag;
		}
		return bi;
	}

	static String xOR(String a, String b, String c) {
		StringBuilder sb = new StringBuilder();
		StringBuilder sb2 = new StringBuilder();
		for (int i = 0; i < a.length(); i++)
			sb.append((a.charAt(i) ^ b.charAt(i)));

		for (int i = 0; i < a.length(); i++)
			sb2.append((sb.charAt(i) ^ c.charAt(i)));
		// System.out.println(a + "\n" + b + "\n" + c + "\n" + sb2 + "\n");
		return sb2.toString();
	}

	static String xOR2(String a, String b) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < a.length(); i++)
			sb.append((a.charAt(i) ^ b.charAt(i)));
		return sb.toString();
	}

	static int cal(String s) {
		return Integer.parseInt(s);
	}

	static byte rot2(byte x) {
		return (byte) (((x & 255) << 2) | ((x & 255) >>> 6));
	}

	static byte g0(byte a, byte b) {
		return rot2((byte) ((a + b) & 255));
	}

	static byte g1(byte a, byte b) {
		return rot2((byte) ((a + b + 1) & 255));
	}

	// order reversed every 8bits
	static long pack(byte[] b, int startindex) {
		/* pack 4 bytes into a 32-bit Word */
		// return (
		// (b[startindex] & 255) |
		// ((b[startindex + 1] & 255) << 8) |
		// ((b[startindex + 2] & 255) << 16) |
		// ((b[startindex + 3] & 255) << 24));
		return (((b[startindex + 3] & 255) << 24)
				| ((b[startindex + 2] & 255) << 16)
				| ((b[startindex + 1] & 255) << 8) | (b[startindex] & 255));
	}

	static void unpack(long a, byte[] b, int startindex) {
		/* unpack bytes from a 32-bit word */
		b[startindex] = (byte) a;
		// System.out.println("unpack " + a + " to b[" + startindex + "] = "
		// + b[startindex]);
		b[startindex + 1] = (byte) (a >>> 8);
		b[startindex + 2] = (byte) (a >>> 16);
		b[startindex + 3] = (byte) (a >>> 24);

	}

	static long f(long input) {
		byte[] x = new byte[4];
		byte[] y = new byte[4];
		unpack(input, x, 0);
		y[1] = g1((byte) ((x[0] ^ x[1]) & 255), (byte) ((x[2] ^ x[3]) & 255));
		y[0] = g0((byte) (x[0] & 255), (byte) (y[1] & 255));
		y[2] = g0((byte) (y[1] & 255), (byte) ((x[2] ^ x[3]) & 255));
		y[3] = g1((byte) (y[2] & 255), (byte) (x[3] & 255));
		return pack(y, 0);
	}

	public static void main(String[] arg) {
		readPairs();
		attacK0T();
		attacK0();
		CopyOfLinFealK1.attacK1T();
		CopyOfLinFealK1.attacK1();
	}
}
