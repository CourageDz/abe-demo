package com.dzy.abedemo.cpabe.test;


public class PolicyTest {
    public static String genPolicy(int attNums, int start) {
        if (attNums == 2)
            return "and " + (start++) + " " + (start++);
        int i = start;
        int k = 1;
        while (k <= attNums) {
            k = k << 1;
        }
        k = k >> 1;
        int max = start + k;
        StringBuffer sb = new StringBuffer();
        while (i < max) {
            String s = sb.toString();
            sb.insert(0, "and ");
            if (s.equals("")) {
                sb.append(i++);
                sb.append(" ");
                sb.append(i++);
            } else {
                String arr[] = s.split(" ");
                for (String c : arr) {
                    if (!c.equals("and")) {
                        sb.append(" ");
                        sb.append(i++);
                    } else
                        sb.append(" and");
                }
            }
        }
        if (i != attNums + start) {
            int diff = attNums + start - i;
            sb.insert(0, "and ");
            sb.append(" ");
            sb.append(genPolicy(diff, i));

        }
        return sb.toString();
    }

    public static String genAttTimePolicy(int attNums, int aaNums, int tAttNums, int start) {
        String normalPolicy = genPolicy(attNums * aaNums, start);
        String[] arr = normalPolicy.split(" ");
        StringBuffer sb = new StringBuffer();
        int count = 0;
        for (String element : arr) {
            if (!element.equals("and")) {
                ++count;
                if (count <= tAttNums)
                    sb.append(element + "t");
                else {
                    sb.append(element);
                    if (count == attNums)
                        count = 0;
                }
                sb.append(" ");
            } else {
                sb.append("and ");
            }
        }
        return sb.toString();
    }

    public static String genAuthTimePolicy(int aaNums, int attNums, int tAANums, int tAttNums, int start) {
        String normalPolicy = genPolicy(attNums * aaNums, start);
        String[] arr = normalPolicy.split(" ");
        StringBuffer sb = new StringBuffer();
        int count = 0;
        int timeCount = 1;
        for (String element : arr) {
            if (!element.equals("and")) {
                ++count;
                if (count <= tAttNums && timeCount <= tAANums) {
                    sb.append(element + "t");
                    if (count == attNums) {
                        count = 0;
                        timeCount++;
                    }

                } else {
                    sb.append(element);
                    if (count == attNums) {
                        count = 0;
                        timeCount++;
                    }
                }
                sb.append(" ");
            } else {
                sb.append("and ");
            }
        }
        return sb.toString();
    }


    public static void main(String[] args) {
//        String result = PolicyTest.genPolicy(10, 0);
//        String test=PolicyTest.genAttTimePolicy(10,3,3,0);
        String test = PolicyTest.genAuthTimePolicy(10, 4, 0, 0, 0);
        System.out.println(test);
    }
}
