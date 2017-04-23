package SM2;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import SM3.*;
/**
 * 
 * @author threads.xui
 *数字签名验签函数
 *@param	IDA_用户A的ID
 *@param	PA_用户A的私钥
 *@param	M1_签名消息
 *@param	r1、s1_签名值
 */
public class check 
{
	
	
	public static String byte2string_16(byte [] buffer)
	{  
        String h = "";         
        for(int i = 0; i < buffer.length; i++)
        {  
            String temp = Integer.toHexString(buffer[i] & 0xFF);  
            if(temp.length() == 1)
            {  
                temp = "0" + temp;  
            }  
            h = h + temp;  
        }            
        return h;      
	}

	
	
	
	
	SM2.param pa = new SM2.param();
	public static boolean check(byte[] IDA, ECPoint PA, byte[] M1, BigInteger r1, BigInteger s1) throws IOException
	{
		if(!step0(PA,M1))
		{
			System.out.println("请输入正确的公钥及消息");
			return false;
		}
		
		if(!step1(r1))
		{
			System.out.println("r1错误！");
			return false;
		};
		
		if(!step1(s1))
		{
			System.out.println("s1错误！");
			return false;
		};//step2，但方法与step1无异
		
		byte[] m1_ = step3(IDA, PA, M1);//第三步，求取M1_
		
		
		
		byte[] e1 = step4(m1_);//第四步，求取e1
		System.out.println("e':"+byte2string_16(e1));
		
		BigInteger t = step5(r1,s1);//第五步，求取t
		System.out.println("t:" + t.toString(16));
		if(!t.equals(BigInteger.ZERO))
		{
			ECPoint x11y11 = step6(s1, t, PA);
			System.out.println("x1':" + x11y11.getX().toBigInteger().toString(16));
			System.out.println("y1':" + x11y11.getY().toBigInteger().toString(16));

			BigInteger R = step7(e1, x11y11.getX().toBigInteger());//这里x1是指用户公钥的x1
			System.out.println("R:" + R.toString(16));
			if(R.equals(r1))
			{
				return true;
			}
		}
		
		return false;
	}

	private static BigInteger step7(byte[] e1, BigInteger b_int) {
		SM2.param para = new SM2.param();
		
		BigInteger r = new BigInteger(byte2string_16(e1),16);//注意此处，转化过程可能会出错误--2017-4-9 08:37:09：第一次运行出错，进行修改
		r = r.add(b_int);
		r = r.mod(para.ecc_n);
		return r;
	}

	public static ECPoint step6(BigInteger s1, BigInteger t, ECPoint pa) 
	{
		//该点求法为s1倍的G+t倍PA
		SM2.param para = new SM2.param();
		ECPoint x11y11,x11y11_1,x11y11_2;
		x11y11_1 = para.ecc_g.multiply(s1);
		System.out.println("x0':" + x11y11_1.getX().toBigInteger().toString(16));
		System.out.println("y0':" + x11y11_1.getY().toBigInteger().toString(16));
		x11y11_2 = pa.multiply(t);
		System.out.println("x00':" + x11y11_2.getX().toBigInteger().toString(16));
		System.out.println("y00':" + x11y11_2.getY().toBigInteger().toString(16));
		x11y11 = x11y11_1.add(x11y11_2);
		return x11y11;
	}


	public static BigInteger step5(BigInteger r1, BigInteger s1) 
	{
		SM2.param pa = new SM2.param();
		BigInteger t = r1;
		t = t.add(s1);
		t = t.mod(pa.ecc_n);
		return t;
	}


	public static byte[] step4(byte[] m1) throws IOException
	{
		SM3.hash ha = new SM3.hash();
		byte[] e1 = ha.hash(m1);
		return e1;
	}

	private static byte[] step3(byte[] ida, ECPoint pa, byte[] m1) throws IOException 
	{
		sign getza = new sign();
		byte[] ZA = getza.getZa(ida, pa);
		SM3.padding joint = new SM3.padding();
		byte[] 	m1_ = joint.joint(ZA, m1);
		return m1_;
	}



	private static boolean step0(ECPoint pa, byte[] m1) 
	{
		if(pa.equals(null))
		{
			return false;
		}
		if(m1.length  == 0 || m1 == null)
		{
			return false;
		}
		return true;
	}

	public static  boolean step1(BigInteger r1) 
	{
		SM2.param pa = new SM2.param();
		BigInteger fir = BigInteger.ONE;
		int lef = r1.compareTo(fir);
		BigInteger one = pa.ecc_n.subtract(BigInteger.ONE);
		int rig = r1.compareTo(one);
		if(lef < 0)
		{
			return false;
		}
		if(rig > 0)
		{
			return false;
		}
		return true;
	}

	public static void main(String[] args) throws IOException 
	{		
		
		sign test = new sign();
		String uids = "ALICE123@YAHOO.COM";
		byte[] uid = uids.getBytes();
		String ms = "message digest";
		byte[] m = ms.getBytes();
		String das = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
		BigInteger dab = new BigInteger(das,16);
		byte[] da = dab.toByteArray();
		sign sig = new sign();
		BigInteger[] resulte = sig.ToSign(uid, da, m);
		System.out.println();
		System.out.println();
		System.out.println("消息M：" + resulte[0].toString(16));
		System.out.println("r：" + resulte[1].toString(16));
		System.out.println("s：" + resulte[2].toString(16));
		System.out.println();
		System.out.println();
		System.out.println();
		System.out.println("开始验签");
		System.out.println();
		check che = new check();
		//提供公钥
		SM2.param para = new SM2.param();
		ECPoint pa = para.ecc_g.multiply(dab);
		if(check(uid, pa, m, resulte[1], resulte[2]))
		{
			System.out.println("验证通过！");
		}
		else
		{
			System.out.println("验证失败！");
		}	
	}
	
}
