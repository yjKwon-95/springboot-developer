package com.korea.todo.security;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.springframework.stereotype.Service;

import com.korea.todo.model.UserEntity;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class TokenProvider {

	//비밀키
	private static final String SECRET_KEY = "d2980a59e9fef528e29e0d5b21b7cedb46291f932e247a4144b89065fbb8dc80d9ab857288d8f29d94f62fc86c554a52cdba369dbf018269b92825e693ad023c62e2dc86bee43c6768a08a7fc72b6cb13a9f79dad3cb23a0a24d2c44e0656be53af5a2d35006e687e606fb662f868c7f994b7d59259b97c144a83b7103dd9cc79146562b6665f8c9a702cf5ff02ffb5181511a12ab28420cc319de23277e0027a14060411e384e6fdd24cb8d69e516e54dcd6aafc1895e2a582004d303f7b906ab2ec5ca0ab547292c193ae4699e3e6768727d9c3e04d95903a9bfa39467043f4b14bc7202bb1d4d1defbbfcdaabf344ec297d2d1f09a371b469811fad09b68b493afe6e38633384f702f51cc2a6d4970239a9bd912eec6f021bf519c51b298a297cbc0765bcbe7630bdb3dda0579c691f95db3aa8a4783689c15abc04751f4bf2331f2d300b8ed36bd558ab8dddd0242176f6ce7c56ad62e048bd1cc0d9ab11cf34bbb6bf3624c5815c66827e3b619da5978e42723b4f7663de29ddad5771397c541cdfe6cb217eef32a49d285c543d52246b072013f9255a879d81c08a222a0f93f2f515903793a17d71714c28b5daa027b1109dea7bc8064ab66c04d7353c1df7f0144f09d13a32c52e93f7461c7adf03e05c080e3ea04a823fef5b3d70286287ef9a7ed1d572df7275eb155b5628d927fce6dd59017dee12a5cf79bdd3b7";
	
	//토큰을 만드는 메서드
	//create()메서드는 JWT라이브러리를 이용해 JWT토큰을 생성한다.
	public String create(UserEntity entity) {
		//토큰 만료시간을 설정
		//현재 시각 + 1일
		//Instant클래스 : 타임스탬프로 찍는다.
		//plus() : 첫번째 인자는 더할 양, 시간단위
		//ChronoUnit 열거형의 DAYS 일 단위를 의미한다.
		Date expiryDate = Date.from(Instant.now().plus(1,ChronoUnit.DAYS));
		
		/*
		 * header
		 * {
		 * "alg:"HS512"
		 * }.
		 * "sub":""
		 * "iss":"todo app",
		 * "iat": 1595733657,
		 * "exp": 1596597657,
		 * }.
		 * 서명
		 * */
		//JWT 토큰을 생성
		return Jwts.builder()
					//header에 들어갈 내용 및 서명을 하기 위한 SECRET_KEY
					.signWith(SignatureAlgorithm.HS512,SECRET_KEY)
					.setSubject(entity.getId()) //sub 클레임 : 사용자 고유 ID
					.setIssuer("todo app") //iss 클레임 : 토큰 발급자
					.setIssuedAt(new Date()) //iat 클레임 : 발급 시각
					.setExpiration(expiryDate) //exp 클레임 : 만료시각
					.compact(); //최종 직렬화된 토큰 문자열 반환
	}
	//validateAndGetUserId() 메서드는 토큰을 디코딩, 파싱 및 위조여부를 확인한다.
	public String validateAndGetUserId(String token) {
		Claims claims = Jwts.parser()
							.setSigningKey(SECRET_KEY) //서명 검증용 키 설정
							.parseClaimsJws(token) //토큰 파싱 및 서명 검증
							.getBody(); //내부 페이로드(Claims)획득
		
		return claims.getSubject(); //sub 클레임(사용자 ID) 반환
	}
}










