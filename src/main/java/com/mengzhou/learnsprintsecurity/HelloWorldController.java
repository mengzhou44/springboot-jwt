package com.mengzhou.learnsprintsecurity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

     @GetMapping(path = "/hello")
     public String sayHello() {
          return "Hello World!";
     }

     @PostMapping(path = "/post")
     public String createName() {
          return "Hello World!";
     }

     @GetMapping("/users/{username}/todos")
     @PreAuthorize("hasRole('ROLE_USER') and #username == authentication.name")
     public List<String> retrieveTodos(@PathVariable String username) {
          return new ArrayList<>(Arrays.asList("Buy grocery", "Go to Gym"));
     }
}
