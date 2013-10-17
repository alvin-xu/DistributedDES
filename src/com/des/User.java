package com.des;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.security.Key;
import java.util.Random;

import javax.crypto.*;
import javax.swing.*;

/**
 * 会话用户类
 * 
 * @author Administrator
 * 
 */
public class User extends JFrame {

 /**
  * 
  */
 private static final long serialVersionUID = 7267580701580372205L;

 private JButton jb; // 按钮
 private JTextArea jta; // 文本显示区
 private Container cta;

 private String orgData; // 保存要加密发送的明文
 private int id; // 用户ID
 private SecretKey secretKey; // 共享会话主密钥
 private boolean working = false; // 是否正在发送或接收
 private ObjectInputStream sendin, receivein; // 发起会话请求的用户(A)的输入输出流
 private ObjectOutputStream sendout, receiveout;// 接受会话请求的用户(B)的输入输出流
 private Socket s;

 Thread thread;
 private int N1, N2; // 随机数

 /**
  * 构造函数
  * 
  * @param id
  *            用户ID
  * @param secretKey
  *            共享会话主密钥
  */
 public User(int id, SecretKey secretKey) {
  this.id = id;
  this.secretKey = secretKey;

  cta = getContentPane();
  jta = new JTextArea();
  jta.setEditable(false);
  jta.setLineWrap(true);
  jb = new JButton("SEND");
  jb.addActionListener(new ActionListener() {
   public void actionPerformed(ActionEvent e) {
    if (!working) {
     SendMsg sm = new SendMsg();
     Thread threadsm = new Thread(sm);
     threadsm.start(); // 启动请求会话线程
    } else
     jta.append("\n正在发送或接收数据，请稍后!");
   }
  });
  cta.setLayout(new BorderLayout());
  cta.add(jb, BorderLayout.SOUTH);
  cta.add(new JScrollPane(jta), BorderLayout.CENTER);
  setSize(300, 300);
  setVisible(true);

  WaitForMsg wfm = new WaitForMsg(id);
  thread = new Thread(wfm);
  thread.start(); // 启动等待会话线程
 }

 /**
  * 从文件中读入要发送的明文
  * 
  * @throws Exception
  */
 private void readin() throws Exception {
  File file = new File("test-1.txt");
  FileInputStream fin;
  fin = new FileInputStream(file);
  ByteArrayOutputStream bout = new ByteArrayOutputStream();
  byte[] tmpbuf = new byte[1024];
  int count = 0;
  while ((count = fin.read(tmpbuf)) != -1) {
   bout.write(tmpbuf, 0, count);
   tmpbuf = new byte[1024];
  }
  fin.close();
  orgData = bout.toString(); // 明文
 }

 /**
  * 利用Socket发送数据,先发送数据长度,再发送数据
  * 
  * @param data
  *            要发送的数据
  * @param out
  *            输出流
  * @throws Exception
  */
 public void sendData(byte[] data, ObjectOutputStream out) throws Exception {
  int num = data.length;
  out.writeInt(num);
  out.flush();

  out.write(data);
  out.flush();
 }

 /**
  * 接收数据,先接收数据长度,然后接收真正的数据
  * 
  * @param in
  *            输入流
  * @return 接收到的数据
  * @throws Exception
  */
 public byte[] recData(ObjectInputStream in) throws Exception {
  int len = in.readInt();
  byte[] rec1 = new byte[len];
  in.read(rec1);

  return rec1;
 }

 /**
  * 产生一个随机数,在0~999之间
  * 
  * @return 产生的随机数
  */
 public int rand() {
  return (new Random()).nextInt() % 1000;
 }

 /**
  * 当请求会话时,调用该函数
  */
 public void send() {
  InetAddress ip;
  int sendport = id == 10000 ? 20000 : 10000; // 请求连接对方的端口号
  Socket connect;

  try {
   ip = InetAddress.getByName("localhost"); // 连接到本机
   connect = new Socket(ip, sendport);
   sendout = new ObjectOutputStream(connect.getOutputStream());// 获得输出流
   sendin = new ObjectInputStream(connect.getInputStream()); // 获得输入流

   N1 = rand(); // 产生随机数N1
   String strSend1 = id + "//" + N1; // 拼接上 IDA
   sendData(strSend1.getBytes(), sendout); // 发送

   byte[] datatemp1 = recData(sendin); // 接收数据,EMKm[Ks/IDA/IDB/f(N1)/N2]
   byte[] datatemp2 = DESUtil.decrypt(secretKey, datatemp1);// 解密数据
   String[] datas = (new String(datatemp2)).split("//"); // 分割数据

   if ((Integer.parseInt(datas[datas.length - 2]) - 1) == N1) // 判断是否为B用户
   {
    byte[] strN2 = f((datas[datas.length - 1]).getBytes())
      .getBytes();// 获得N2,并进行F变换
    Key key = DESUtil.generateKey(datas[0]); // 生成唯一的Key
    SecretKey secretkey_Ks = DESUtil.generateSecretKey(key
      .getEncoded()); // 生成本次会话密钥
    byte[] strSend3 = DESUtil.encrypt(secretkey_Ks, strN2); // 加密变化后的N2
    sendData(strSend3, sendout); // 发送N2

    readin(); // 从文件中读入明文

    byte[] strSend6 = DESUtil.encrypt(secretkey_Ks, orgData
      .getBytes()); // 用会话密钥加密明文
    sendData(strSend6, sendout); // 发送

    sendout.close();
    sendin.close();
    connect.close();
   } else {
    JOptionPane.showMessageDialog(null, "获得N1有误，可能不是B用户或解析错误");
   }
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
  }
 }

 /**
  * 当收到会话请求时，调用该函数
  * 
  * @param data
  */
 public void dealWith(String data) {
  String[] datas = data.split("//"); // 分割收到的数据，IDA//N1
  int keyNum = rand(); // 产生随机数，用于生成Key
  Key key = DESUtil.generateKey(keyNum + ""); // 生成Key
  SecretKey secretkey_Ks = DESUtil.generateSecretKey(key.getEncoded()); // 用Key生成密钥

  N2 = rand(); // 生成随机数N2
  String strSend1 = keyNum + "//" + (new String(datas[0])) + "//" + id
    + "//" + f(datas[1].getBytes()) + "//" + N2; // 拼接
  // Ks//IDA//IDB//f(N1)//N2
  byte[] strSend3 = DESUtil.encrypt(secretKey, strSend1.getBytes()); // 加密明文

  try {
   sendData(strSend3, receiveout); // 发送

   byte[] datatemp1 = recData(receivein); // 得到F(N2)
   byte[] recN2 = DESUtil.decrypt(secretkey_Ks, datatemp1); // 利用会话密钥解密
   int tempN2 = Integer.parseInt(new String(recN2)) - 1; // 做F的逆变化

   if (tempN2 == N2) // 判断对方是否为A
   {
    byte[] datatemp2 = recData(receivein); // 接收数据
    byte[] result = DESUtil.decrypt(secretkey_Ks, datatemp2); // 解密
    jta.append("\n收到数据：" + new String(result));
   } else {
    JOptionPane.showMessageDialog(null, "对方不是A或者N2解释错误");
   }
  } catch (Exception e) {
   e.printStackTrace();
  }
 }

 /**
  * F函数加1变换
  * 
  * @param n
  *            要变换的数值
  * @return 变换完的数值
  */
 public String f(byte[] n) {
  String temp = (new String(n)).trim();
  int a = Integer.parseInt(temp);
  a++;
  return ("" + a);
 }

 /**
  * 发起会话请求的线程
  * 
  * @author Administrator
  * 
  */
 private class SendMsg implements Runnable {
  public void run() {
   // TODO Auto-generated method stub
   jta.append("\n正在发送数据。");
   working = true;
   send();
   jta.append("\n数据发送完成。");
   working = false;
  }
 }

 /**
  * 等待会话请求的线程
  * 
  * @author Administrator
  * 
  */
 private class WaitForMsg implements Runnable {
  byte[] datatemp1 = null;
  private ServerSocket receiveSocket;
  private String rev;

  /**
   * 构造函数
   * 
   * @param port
   *            监听的端口号
   */
  public WaitForMsg(int port) {
   try {
    receiveSocket = new ServerSocket(port, 5);
   } catch (IOException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
   }
  }

  /**
   * 循环监听会话请求，如果有会话，处理会话
   */
  public void run() {
   // TODO Auto-generated method stub
   while (true) {
    try {
     s = receiveSocket.accept();

     receiveout = new ObjectOutputStream(s.getOutputStream());
     receivein = new ObjectInputStream(s.getInputStream());

     rev = new String(recData(receivein));
     jta.append("\n收到会话请求，正在接收数据。");
     working = true;
     dealWith(rev);
     working = false;
    } catch (Exception e1) {
     e1.printStackTrace();
     JOptionPane.showMessageDialog(null, "出错");
     System.exit(0);
    }
   }
  }
 }
}