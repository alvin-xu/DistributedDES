package com.des;

import javax.crypto.SecretKey;
import javax.swing.JFrame;

/**
 * 测试类
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
  // 为A,B产生共享的会话主密钥
  SecretKey key = DESUtil.generateSecretKey(DESUtil.generateKey("1234")
    .getEncoded());
  User u1 = new User(10000, key); // 初始化用户和共享会话主密钥
  User u2 = new User(20000, key); // 初始化用户和共享会话主密钥

  u1.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
  u2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

 }

}