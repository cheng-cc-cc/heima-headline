package jmu.lsk.app.gateway.filter;

import com.alibaba.nacos.api.utils.StringUtils;
import io.jsonwebtoken.Claims;
import jmu.lsk.app.gateway.utils.AppJwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizeFilter implements Ordered, GlobalFilter {
    // 定义一个常量，作为存储开始时间的键
    private static final String START_TIME = "startTime";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1.获取request和response对象
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        // **前置逻辑 (Pre)**: 在调用 chain.filter 之前
        // 记录请求开始时间，并存入 exchange 的属性中，以便后置逻辑使用
        exchange.getAttributes().put(START_TIME, System.currentTimeMillis());
        log.info("请求开始时间已记录");

        //2.判断是否是登录
        if(request.getURI().getPath().contains("/login")){
            //放行
            return chain.filter(exchange);
        }


        //3.获取token
        String token = request.getHeaders().getFirst("token");

        //4.判断token是否存在
        if(StringUtils.isBlank(token)){
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        //5.判断token是否有效
        try {
            Claims claimsBody = AppJwtUtil.getClaimsBody(token);
            //是否是过期
            int result = AppJwtUtil.verifyToken(claimsBody);
            if(result == 1 || result  == 2){
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            Object userId = claimsBody.get("id");
            ServerHttpRequest serverHttpRequest = request.mutate().headers(httpHeaders -> {
                httpHeaders.add("userId",userId+"");
            }).build();

            exchange.mutate().request(serverHttpRequest).build();


        }catch (Exception e){
            e.printStackTrace();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        //6.放行
        return chain.filter(exchange).then(
                Mono.fromRunnable(() -> {
                    // **后置逻辑 (Post)**: 在 then 方法内执行
                    Long startTime = exchange.getAttribute(START_TIME);
                    if (startTime != null) {
                        long duration = System.currentTimeMillis() - startTime;
                        log.info("请求 {} 处理完毕，总耗时: {} ms",
                                exchange.getRequest().getURI().getRawPath(), duration);
                        // 你也可以选择将耗时等信息添加到响应头中
                        exchange.getResponse().getHeaders().add("X-Response-Duration", duration + "ms");
                    }
                })
        );
    }

    /**
     * 优先级设置  值越小  优先级越高
     * @return
     */
    @Override
    public int getOrder() {
        return 0;
    }
}
