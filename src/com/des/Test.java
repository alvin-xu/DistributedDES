package com.des;

import javax.crypto.SecretKey;
import javax.swing.JFrame;

/**
 * ������
 * 
 * @author Administrator
 * 
 */
public class Test {

 /**
  * @param args
  */
 public static void main(String[] args) {
  // TODO Auto-generated method stub
  // ΪA,B��������ĻỰ����Կ
  SecretKey key = DESUtil.generateSecretKey(DESUtil.generateKey("1234")
    .getEncoded());
  User u1 = new User(10000, key); // ��ʼ���û��͹���Ự����Կ
  User u2 = new User(20000, key); // ��ʼ���û��͹���Ự����Կ

  u1.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
  u2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

 }

}