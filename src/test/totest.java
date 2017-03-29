package test;

public class totest 
{
	public static SM3.param pa = new SM3.param();

	public static void main(String[] args)
	{
		byte[] source;
		String id = "ALICE123@YAHOO.COM";
		source = id.getBytes();
		System.out.println(pa.byte2hex(source));
		int len = source.length*8;
		byte[] entla = new byte[2];
		entla[0] = (byte) (len>>8);
		entla[1] = (byte)(len);
		System.out.println(pa.byte2hex(entla));

		
		
		String out = new String(String.valueOf(len));
		System.out.println(out);
	}
}
