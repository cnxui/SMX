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
	SM2.param pa = new SM2.param();
	public boolean check(byte[] IDA, ECPoint PA, byte[] M1, BigInteger r1, BigInteger s1)
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
		
		BigInteger t = step5(r1,s1);//第五步，求取t
		if(!t.equals(BigInteger.ZERO))
		{
			ECPoint x11y11 = step6(s1, t, PA);
			BigInteger R = step7(e1, x1);//这里x1是指用户公钥的x1
			if(R == r1)
			{
				return true;
			}
		}
		
		return false;
	}


	public ECPoint step6(BigInteger s1, BigInteger t, ECPoint pa) 
	{
		//该点求法为s1倍的G+t倍PA
		SM2.param para = new SM2.param();
		ECPoint x11y11,x11y11_1,x11y11_2;
		x11y11_1 = para.ecc_g.multiply(s1);
		x11y11_2 = pa.multiply(t);
		x11y11 = x11y11_1.add(x11y11_2);
		return x11y11;
	}


	public BigInteger step5(BigInteger r1, BigInteger s1) 
	{
		SM2.param pa = new SM2.param();
		BigInteger t = r1;
		t = t.add(s1);
		t = t.mod(pa.ecc_n);
		return t;
	}


	public byte[] step4(byte[] m1) throws IOException
	{
		SM3.hash ha = new SM3.hash();
		byte[] e1 = ha.hash(m1);
		return e1;
	}

	private byte[] step3(byte[] ida, ECPoint pa, byte[] m1) throws IOException 
	{
		sign getza = new sign();
		byte[] ZA = getza.getZa(ida, pa);
		SM3.padding joint = new SM3.padding();
		byte[] 	m1_ = joint.joint(ZA, m1);
		return m1_;
	}



	private boolean step0(ECPoint pa, byte[] m1) 
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

	public  boolean step1(BigInteger r1) 
	{
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

	public static void main(String[] args) 
	{
//		BigInteger fir = new BigInteger("1");
//		BigInteger r1 = new BigInteger("1");
//		int re = r1.compareTo(fir);
//		System.out.println(re);
	}
	

}
