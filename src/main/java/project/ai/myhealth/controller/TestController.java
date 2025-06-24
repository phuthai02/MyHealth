package project.ai.myhealth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import project.ai.myhealth.service.redis.RedisService;

import java.security.Principal;
import java.util.concurrent.TimeUnit;

@RestController
public class TestController {

    @Autowired
    private RedisService redisTestService;

    @GetMapping("/admin")
    public String admin(Principal principal) {
        return "Hello Admin: " + principal.getName();
    }

    @GetMapping("/user")
    public String user(Principal principal) {
        return "Hello User: " + principal.getName();
    }

    @GetMapping("public/set")
    public Boolean set(@RequestParam String key, @RequestParam String value) {
        return redisTestService.setWithExpiration(key, value, 10000L, TimeUnit.MILLISECONDS);
    }

    @GetMapping("public/get")
    public String get(@RequestParam String key) {
        return redisTestService.get(key);
    }

    @GetMapping("public/del")
    public Boolean del(@RequestParam String key) {
        return redisTestService.del(key);
    }
}
