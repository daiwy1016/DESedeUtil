package org.it315;
public class TestPackage 
{
    public static void main(String[] args) 
    {
        new org.it315.example.Test().print();
        System.out.println(new org.it315.example.Test().decode("16"));
    }
}