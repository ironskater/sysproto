package sysproto.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 401 場景：
     * 未登入用戶試圖訪問需要登入的頁面
     * Token 過期或無效
     *
     * 403 場景：
     * 普通用戶試圖訪問管理員頁面
     * 已登入用戶訪問未授權的資源
     * 在您的情況下，收到 403 表示您可能已經通過了認證（已登入），但是沒有足夠的權限訪問該資源。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            /**
             * 無狀態（Stateless）模式：
             * 應用程序不會創建或使用HTTP Session
             * 每個請求都應該包含所有必要的認證信息
             * 特別適合用於REST API或JWT認證的場景
             *
             * 為什麼要使用STATELESS？
             * 提高可擴展性：不需要在服務器端存儲會話信息
             * 適合微服務架構：各個服務之間不需要共享會話狀態
             * 更好的負載均衡：請求可以被分發到任何服務器節點
             *
             * SessionCreationPolicy有其他選項：
             * ALWAYS：總是創建會話
             * IF_REQUIRED：需要時才創建（默認值）
             * NEVER：不會創建會話，但如果已經存在則會使用
             * STATELESS：完全不使用會話
             * 在您的配置中使用STATELESS表明這是一個RESTful的應用程序，可能會使用像JWT這樣的token來進行身份驗證，而不是依賴傳統的session-cookie機制。
             */
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/loginJwt",
                    "/loginSession",
                    "/logout",
                    "/public/**").permitAll()  // 允許所有人訪問登入和登出端點
                .anyRequest().authenticated()  // 其他所有請求都需要認證
            )
            .logout(logout -> logout.disable());

        // 登出處理器
        // .logout(logout -> logout
        //     .logoutUrl("/logout")
        // );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
        AuthenticationConfiguration config) throws Exception {

        return config.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build()
        );
    }
}