import java.util.Random;

public class forBreak{
    public static void main(String[] args) { 
          outer: //���ѭ����ʶ
          for (int i = 0; i < 10; i++) { 
                System.out.println("\nouter_loop:" + i); 
                inner: //�ڲ�ѭ����ʶ
                for (int k = 0; i < 10; k++) { 
                      System.out.print(k + " "); 
                      int x = new Random().nextInt(10); 
                      if (x > 7) { 
                            System.out.print(" >>x == " + x + "������innerѭ������������ִ��outerѭ���ˣ�"); 
                            continue outer; //����ִ��outer��ʶ��ѭ��
                    } 
                    if (x == 1) { 
                            System.out.print(" >>x == 1����������������outer��innerѭ����"); 
                            break outer; //����outer��ʶ��ѭ��
                      } 
                } 
          } 
          System.out.println("------>>>����ѭ��ִ����ϣ�"); 
    } 
    }