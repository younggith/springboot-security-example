package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

// 구글 로그인이 완료된 뒤의 후처리가 필요함. 1. 코드 받기(인증), 2. 엑세스 토큰(권한이생김), 
// 3. 사용자프로필 정보를 가져오고 4-1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함.
// 4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소), 백화점 -> (vip등급, 일반등급)

@Configuration
@EnableWebSecurity	// 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)	// secure 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
public class SecurityConfig {
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws
		Exception {
		http
			.csrf().disable()	// csrf 토큰 비활성화 (테스트시엔 걸어두는게 좋음)
			.authorizeHttpRequests()
			.requestMatchers("/user/**").authenticated()	// 인증만 되면 들어갈 수 있는 주소!!
			.requestMatchers("/manager/**") .hasAnyRole("ADMIN", "MANAGER")
			.requestMatchers("/admin/**") .hasRole("ADMIN")
			.anyRequest().permitAll()	// 위경로가 아닌 다른 경로의 요청은 모두 허용
			.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login")	// /login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줍니다.
			.defaultSuccessUrl("/")
			.and()
			.oauth2Login()
			.loginPage("/loginForm")
			.userInfoEndpoint()
			.userService(principalOauth2UserService);// 구글 로그인이 완료된 뒤의 후처리가 필요함.  Tip. 코드안받음X (엑세스토큰+사용자프로필정보)O
			
		return http.build();
	}
	
}
