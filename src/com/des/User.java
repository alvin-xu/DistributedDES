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
 * �Ự�û���
 * 
 * @author Administrator
 * 
 */
public class User extends JFrame {

 /**
  * 
  */
 private static final long serialVersionUID = 7267580701580372205L;

 private JButton jb; // ��ť
 private JTextArea jta; // �ı���ʾ��
 private Container cta;

 private String orgData; // ����Ҫ���ܷ��͵�����
 private int id; // �û�ID
 private SecretKey secretKey; // ����Ự����Կ
 private boolean working = false; // �Ƿ����ڷ��ͻ����
 private ObjectInputStream sendin, receivein; // ����Ự������û�(A)�����������
 private ObjectOutputStream sendout, receiveout;// ���ܻỰ������û�(B)�����������
 private Socket s;

 Thread thread;
 private int N1, N2; // �����

 /**
  * ���캯��
  * 
  * @param id
  *            �û�ID
  * @param secretKey
  *            ����Ự����Կ
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
     threadsm.start(); // ��������Ự�߳�
    } else
     jta.append("\n���ڷ��ͻ�������ݣ����Ժ�!");
   }
  });
  cta.setLayout(new BorderLayout());
  cta.add(jb, BorderLayout.SOUTH);
  cta.add(new JScrollPane(jta), BorderLayout.CENTER);
  setSize(300, 300);
  setVisible(true);

  WaitForMsg wfm = new WaitForMsg(id);
  thread = new Thread(wfm);
  thread.start(); // �����ȴ��Ự�߳�
 }

 /**
  * ���ļ��ж���Ҫ���͵�����
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
  orgData = bout.toString(); // ����
 }

 /**
  * ����Socket��������,�ȷ������ݳ���,�ٷ�������
  * 
  * @param data
  *            Ҫ���͵�����
  * @param out
  *            �����
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
  * ��������,�Ƚ������ݳ���,Ȼ���������������
  * 
  * @param in
  *            ������
  * @return ���յ�������
  * @throws Exception
  */
 public byte[] recData(ObjectInputStream in) throws Exception {
  int len = in.readInt();
  byte[] rec1 = new byte[len];
  in.read(rec1);

  return rec1;
 }

 /**
  * ����һ�������,��0~999֮��
  * 
  * @return �����������
  */
 public int rand() {
  return (new Random()).nextInt() % 1000;
 }

 /**
  * ������Ựʱ,���øú���
  */
 public void send() {
  InetAddress ip;
  int sendport = id == 10000 ? 20000 : 10000; // �������ӶԷ��Ķ˿ں�
  Socket connect;

  try {
   ip = InetAddress.getByName("localhost"); // ���ӵ�����
   connect = new Socket(ip, sendport);
   sendout = new ObjectOutputStream(connect.getOutputStream());// ��������
   sendin = new ObjectInputStream(connect.getInputStream()); // ���������

   N1 = rand(); // ���������N1
   String strSend1 = id + "//" + N1; // ƴ���� IDA
   sendData(strSend1.getBytes(), sendout); // ����

   byte[] datatemp1 = recData(sendin); // ��������,EMKm[Ks/IDA/IDB/f(N1)/N2]
   byte[] datatemp2 = DESUtil.decrypt(secretKey, datatemp1);// ��������
   String[] datas = (new String(datatemp2)).split("//"); // �ָ�����

   if ((Integer.parseInt(datas[datas.length - 2]) - 1) == N1) // �ж��Ƿ�ΪB�û�
   {
    byte[] strN2 = f((datas[datas.length - 1]).getBytes())
      .getBytes();// ���N2,������F�任
    Key key = DESUtil.generateKey(datas[0]); // ����Ψһ��Key
    SecretKey secretkey_Ks = DESUtil.generateSecretKey(key
      .getEncoded()); // ���ɱ��λỰ��Կ
    byte[] strSend3 = DESUtil.encrypt(secretkey_Ks, strN2); // ���ܱ仯���N2
    sendData(strSend3, sendout); // ����N2

    readin(); // ���ļ��ж�������

    byte[] strSend6 = DESUtil.encrypt(secretkey_Ks, orgData
      .getBytes()); // �ûỰ��Կ��������
    sendData(strSend6, sendout); // ����

    sendout.close();
    sendin.close();
    connect.close();
   } else {
    JOptionPane.showMessageDialog(null, "���N1���󣬿��ܲ���B�û����������");
   }
  } catch (Exception e) {
   // TODO Auto-generated catch block
   e.printStackTrace();
  }
 }

 /**
  * ���յ��Ự����ʱ�����øú���
  * 
  * @param data
  */
 public void dealWith(String data) {
  String[] datas = data.split("//"); // �ָ��յ������ݣ�IDA//N1
  int keyNum = rand(); // �������������������Key
  Key key = DESUtil.generateKey(keyNum + ""); // ����Key
  SecretKey secretkey_Ks = DESUtil.generateSecretKey(key.getEncoded()); // ��Key������Կ

  N2 = rand(); // ���������N2
  String strSend1 = keyNum + "//" + (new String(datas[0])) + "//" + id
    + "//" + f(datas[1].getBytes()) + "//" + N2; // ƴ��
  // Ks//IDA//IDB//f(N1)//N2
  byte[] strSend3 = DESUtil.encrypt(secretKey, strSend1.getBytes()); // ��������

  try {
   sendData(strSend3, receiveout); // ����

   byte[] datatemp1 = recData(receivein); // �õ�F(N2)
   byte[] recN2 = DESUtil.decrypt(secretkey_Ks, datatemp1); // ���ûỰ��Կ����
   int tempN2 = Integer.parseInt(new String(recN2)) - 1; // ��F����仯

   if (tempN2 == N2) // �ж϶Է��Ƿ�ΪA
   {
    byte[] datatemp2 = recData(receivein); // ��������
    byte[] result = DESUtil.decrypt(secretkey_Ks, datatemp2); // ����
    jta.append("\n�յ����ݣ�" + new String(result));
   } else {
    JOptionPane.showMessageDialog(null, "�Է�����A����N2���ʹ���");
   }
  } catch (Exception e) {
   e.printStackTrace();
  }
 }

 /**
  * F������1�任
  * 
  * @param n
  *            Ҫ�任����ֵ
  * @return �任�����ֵ
  */
 public String f(byte[] n) {
  String temp = (new String(n)).trim();
  int a = Integer.parseInt(temp);
  a++;
  return ("" + a);
 }

 /**
  * ����Ự������߳�
  * 
  * @author Administrator
  * 
  */
 private class SendMsg implements Runnable {
  public void run() {
   // TODO Auto-generated method stub
   jta.append("\n���ڷ������ݡ�");
   working = true;
   send();
   jta.append("\n���ݷ�����ɡ�");
   working = false;
  }
 }

 /**
  * �ȴ��Ự������߳�
  * 
  * @author Administrator
  * 
  */
 private class WaitForMsg implements Runnable {
  byte[] datatemp1 = null;
  private ServerSocket receiveSocket;
  private String rev;

  /**
   * ���캯��
   * 
   * @param port
   *            �����Ķ˿ں�
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
   * ѭ�������Ự��������лỰ������Ự
   */
  public void run() {
   // TODO Auto-generated method stub
   while (true) {
    try {
     s = receiveSocket.accept();

     receiveout = new ObjectOutputStream(s.getOutputStream());
     receivein = new ObjectInputStream(s.getInputStream());

     rev = new String(recData(receivein));
     jta.append("\n�յ��Ự�������ڽ������ݡ�");
     working = true;
     dealWith(rev);
     working = false;
    } catch (Exception e1) {
     e1.printStackTrace();
     JOptionPane.showMessageDialog(null, "����");
     System.exit(0);
    }
   }
  }
 }
}