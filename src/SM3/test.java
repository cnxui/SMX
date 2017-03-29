package SM3;

import java.io.IOException;
import java.util.Scanner;

public class test {

	public static void main(String[] args) throws IOException 
	{
		// TODO Auto-generated method stub
		param pa = new param();
		padding pad = new padding();
		hash sm3 = new hash();
		
		byte[] source,value;
		
		System.out.println("请输入消息");
		Scanner scan = new Scanner(System.in);
		String str = scan.next(); 
		source = str.getBytes();

		value = sm3.hash(source);
		System.out.println("散列值为：" + pa.byte2hex(value));
	}

}
