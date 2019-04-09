package com.dzy.abedemo.cpabe.policy;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PolicyComResults {
    private List<Integer> s1;
    private List<Integer> s2;
    private List<Integer> s3;
    private Set<String> sm1;
    private Set<String> sm2;

    public PolicyComResults() {
        s1 = new ArrayList<>();
        s2 = new ArrayList<>();
        s3 = new ArrayList<>();
        sm1 = new HashSet<>();
        sm2 = new HashSet<>();
    }

    public List<Integer> getS1() {
        return s1;
    }

    public List<Integer> getS2() {
        return s2;
    }

    public List<Integer> getS3() {
        return s3;
    }

    public Set<String> getSm1() {
        return sm1;
    }

    public Set<String> getSm2() {
        return sm2;
    }
}
