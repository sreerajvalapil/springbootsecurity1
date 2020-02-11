package com.sree.springboot1.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.print.DocFlavor;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/sree")
public class SreeController {
    @GetMapping("/bankList")
    public List<String> getBankList() {
        return Arrays.asList("SEB","SwedBank");
    }

}
