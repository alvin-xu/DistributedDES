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
  * ������Կ
  * 
  * @return
  *   ��Կ
  */
 public static Key generateKey(String str){
  try {
   KeyGenerator kg = KeyGenerator.getInstance("DES");
   SecureRandom sr = new SecureRandom(str.getBytes());//�����Դ
   kg.init(sr);//��ʼ��
   
   Key key = kg.generateKey();//������Կ
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
   //����һ����Կ����
   fac = SecretKeyFactory.getInstance("DES");
   DESKeySpec spec = new DESKeySpec(key);//��ԭʼ�ܳ����ݴ���һ��DESKeySpec����
   
   return fac.generateSecret(spec);
   
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
   return null;
  }
 }
 /**
  * ����
  * 
  * @param key
  *    ��Կ
  * @param data
  *    �����ܵ�����
  * @return
  *    ���ܺ������
  */
 public static byte[] encrypt(SecretKey secretKey,byte[] data){
  Cipher cipher;
  try {
   cipher = Cipher.getInstance("DES");
   cipher.init(Cipher.ENCRYPT_MODE, secretKey);//��ʼ��cipher,����ģʽ,�����ó�ʼ������
   
   return cipher.doFinal(data);
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
   return null;
  }
  
 }
 
 /**
  * ����
  * 
  * @param key
  *    ��Կ
  * @param data
  *    �����ܵ�����
  * @return
  *    ���ܺ������
  */
 public static byte[] decrypt(SecretKey secretKey,byte[] data){
            Cipher cipher = null;
   try {
    cipher = Cipher.getInstance("DES");
    cipher.init(Cipher.DECRYPT_MODE,secretKey);//��ʼ��cipher,����ģʽ,�����ó�ʼ������
    
    return cipher.doFinal(data);
   } 
   catch (Exception e){
    e.printStackTrace();
   }
           
            return null;
 }
 
  /**
     * ת��16����
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