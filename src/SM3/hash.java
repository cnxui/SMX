package SM3;

import java.io.IOException;
import java.util.Arrays;
/**
 * 
 * @author XUI
 *散列部分
 */
public class hash 
{
	param pa = new param();
	CompressFunc CF = new CompressFunc();

	
	public byte[] hash(byte[] m) throws IOException
	{
		byte[] M = m;
		//System.out.println("需要进行散列的消息（扩充之后）"+ param.byte2hex(M));
		int n = (M.length * 8)/512; //迭代次数
		byte[] B;
		byte[] VI = pa.IV.toByteArray();//获取初始变量
		byte[] VII = null;
		for(int i = 0; i<n; i++)
		{
			B = Arrays.copyOfRange(M, i * 64, (i + 1) * 64);
			VII = CF.cf(VI,B);
			VI = VII;
			System.out.println("第" + i +"轮压缩后的值:" + pa.byte2hex(VII));
		}
		
		return VII;
	}
	
//    public static void main(String[] args)
//    {
////    	测试private和public区别
////    	param params = new param();
////    	System.out.println(params.IV);
//    }

}