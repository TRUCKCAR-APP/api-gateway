package escuelaing.edu.co.api_gateway.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitResponseFilterTest {

    private static HttpHeaders limiter(String replenishRate, String requestedTokens) {
        HttpHeaders headers = new HttpHeaders();
        if (replenishRate != null) {
            headers.set(RateLimitResponseFilter.REPLENISH_RATE, replenishRate);
        }
        if (requestedTokens != null) {
            headers.set(RateLimitResponseFilter.REQUESTED_TOKENS, requestedTokens);
        }
        return headers;
    }

    @Test
    void retryAfterIsTheTimeToRefillOneRequestRoundedUp() {
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("1", "1"))).isEqualTo(1);
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("5", "1"))).isEqualTo(1);   // 0,2 s → 1
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("1", "3"))).isEqualTo(3);
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("2", "3"))).isEqualTo(2);   // 1,5 s → 2
    }

    @Test
    void withoutLimiterHeadersOrWithNonsenseItFallsBackToOneSecond() {
        assertThat(RateLimitResponseFilter.retryAfterSeconds(new HttpHeaders())).isEqualTo(1);
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("abc", "1"))).isEqualTo(1);
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("0", "1"))).isEqualTo(1);
        assertThat(RateLimitResponseFilter.retryAfterSeconds(limiter("1", null))).isEqualTo(1);
    }
}
