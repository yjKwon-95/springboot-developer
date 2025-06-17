package com.korea.todo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration //스프링에서 해당 클래스를 설정 클래스로 인식하고 bean으로 등록함
//WebMvcConfigurer 스프링 MVC의 기본설정을 내가 조절하고 싶을 때 사용한다.
//스프링 MVC는 여러가지 기본설정(뷰 리졸버, 메시지 컨버터, CORS등)을 가지고 있다.
public class WebMvcConfig implements WebMvcConfigurer{
	private final long MAX_AGE_SECS = 3600; //브라우저가 CORS 요청 결과를 캐싱하는 최대 시간 설정
	//캐싱이란 : 자주 쓰는 정보를 미리 저장해 뒀다가, 다음에 같은 정보가 필요할 때
	//저장소에서 꺼내쓰는 기법
	
	//registry : 스프링이 내부에서 생성해서 넘겨주는 CORS설정용 객체이다.
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		//addMapping("/**") : 백엔드 프로젝트 모든 경로에 대해 CORS 설정을 적용
		registry.addMapping("/**")
			//.allowedOrigins("http://localhost:3000") : React 어플리케이션이 실행되는 도메인에서 오는 요청을 허용
			.allowedOrigins("http://localhost:3000")
			//.allowedMethods("GET","PUT","POST","DELETE") : HTTP메서드를 허용
			.allowedMethods("GET","PUT","POST","DELETE")
			//.allowedHeaders("*") : 모든 헤더를 허용
			.allowedHeaders("*")
			//.allowCredentials(true): 쿠키나 인증 정보를 포함한 요청을 허용
			.allowCredentials(true)
			//.maxAge(MAX_AGE_SECS); : 브라우저가 서버로부터 받은 응답을 일정 시간 동안 저장해두고
			//그 시간 내에 동일한 요청이 있을 경우 서버에 다시 요청하지 않고
			//저장된 응답을 재사용한다.
			.maxAge(MAX_AGE_SECS);
		
	}

}






