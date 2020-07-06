import java.util.Random;

public class forBreak{
    public static void main(String[] args) { 
          outer: //外层循环标识
          for (int i = 0; i < 10; i++) { 
                System.out.println("\nouter_loop:" + i); 
                inner: //内层循环标识
                for (int k = 0; i < 10; k++) { 
                      System.out.print(k + " "); 
                      int x = new Random().nextInt(10); 
                      if (x > 7) { 
                            System.out.print(" >>x == " + x + "，结束inner循环，继续迭代执行outer循环了！"); 
                            continue outer; //继续执行outer标识的循环
                    } 
                    if (x == 1) { 
                            System.out.print(" >>x == 1，跳出并结束整个outer和inner循环！"); 
                            break outer; //跳出outer标识的循环
                      } 
                } 
          } 
          System.out.println("------>>>所有循环执行完毕！"); 
    } 
    }