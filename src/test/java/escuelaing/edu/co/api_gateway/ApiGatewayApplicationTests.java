package escuelaing.edu.co.api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@TestPropertySource(properties = {
		"app.jwt.secret=dGVzdC1qd3Qtc2VjcmV0LWtleS1mb3ItdHJ1Y2tkYXI="
})
class ApiGatewayApplicationTests {

	@Test
	void contextLoads() {
	}

}
