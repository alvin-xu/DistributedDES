package com.des;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class DESUtil {

 /**
  * 生成密钥
  * 
  * @return
  *   密钥
  */
 public static Key generateKey(String str){
  try {
   KeyGenerator kg = KeyGenerator.getInstance("DES");
   SecureRandom sr = new SecureRandom(str.getBytes());//随机数源
   kg.init(sr);//初始化
   
   Key key = kg.generateKey();//生成密钥
   return key;
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
   return null;
  }
 }
 
 /**
  * 
  * @param key
  * @return
  */
 public static SecretKey generateSecretKey(byte[] key){
  SecretKeyFactory fac = null;
  try {
   //创建一个密钥工厂
   fac = SecretKeyFactory.getInstance("DES");
   DESKeySpec spec = new DESKeySpec(key);//从原始密匙数据创建一个DESKeySpec对象
   
   return fac.generateSecret(spec);
   
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
   return null;
  }
 }
 /**
  * 加密
  * 
  * @param key
  *    密钥
  * @param data
  *    待加密的明文
  * @return
  *    加密后的密文
  */
 public static byte[] encrypt(SecretKey secretKey,byte[] data){
  Cipher cipher;
  try {
   cipher = Cipher.getInstance("DES");
   cipher.init(Cipher.ENCRYPT_MODE, secretKey);//初始化cipher,加密模式,并设置初始化向量
   
   return cipher.doFinal(data);
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
   return null;
  }
  
 }
 
 /**
  * 解密
  * 
  * @param key
  *    密钥
  * @param data
  *    待解密的密文
  * @return
  *    解密后的明文
  */
 public static byte[] decrypt(SecretKey secretKey,byte[] data){
            Cipher cipher = null;
   try {
    cipher = Cipher.getInstance("DES");
    cipher.init(Cipher.DECRYPT_MODE,secretKey);//初始化cipher,解密模式,并设置初始化向量
    
    return cipher.doFinal(data);
   } 
   catch (Exception e){
    e.printStackTrace();
   }
           
            return null;
 }
 
  /**
     * 转换16进制
     * 
     * @param data
     * @return
     */
    public static byte[] getHexString(byte[] data){
      String s = new String();
         for(int i=0;i<data.length;i++){
          s += Integer.toHexString(data[i]& 0xFF);
         }
         
         return s.getBytes();
    }
}