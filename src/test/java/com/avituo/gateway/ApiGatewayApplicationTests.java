package com.avituo.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
		"app.jwt.secret=tests_secret_key_for_hs256_auth_12345",
		"app.jwt.issuer=https://auth.example.test",
		"app.jwt.audience=tcc-api-gateway",
		"app.gateway.key=test-gateway-internal-key"
})
class ApiGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
