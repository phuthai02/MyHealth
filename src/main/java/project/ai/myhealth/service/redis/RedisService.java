package project.ai.myhealth.service.redis;

import java.util.concurrent.TimeUnit;

public interface RedisService {
    Boolean set(String key, String value);
    String get(String key);
    Boolean del(String key);
    Boolean exists(String key);
    Boolean setWithExpiration(String key, String value, Long timeOut, TimeUnit timeUnit);
}
