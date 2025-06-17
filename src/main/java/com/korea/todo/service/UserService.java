package com.korea.todo.service;

import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.korea.todo.model.UserEntity;
import com.korea.todo.persistence.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

	//repository 생성자 주입하기
	private final UserRepository repository;
	
	//유저의 추가
	//회원가입 화면에서 넘어오는 정보
	public UserEntity create(UserEntity entity) {
		//주어진 UserEntity가 null거나 또는 username이 null인경우 예외를 발생시킨다.
		if(entity == null || entity.getUsername() == null) {
			throw new RuntimeException("Invalid arguments");
		}
		
		//entity에서 username을 가져온다.
		final String username = entity.getUsername();
		
		//주어진 username이 이미 존재하는 경우, 경로 로그를 남기고 예외를 던진다.
		if(repository.existsByUsername(username)) {
			log.warn("Username already exists {}",username);
			throw new RuntimeException("Username already exists");
		}
		
		//username이 중복되지 않았다면, entity객체를 데이터베이스에 추가
		return repository.save(entity);
	}
	
	//주어진 username과 password를 이용해서 entity를 조회한다.
//	public UserEntity getByCredential(String username, String password) {
//		return repository.findByUsernameAndPassword(username, password);
//	}
	
	public UserEntity getByCredentials(String username, String password, final PasswordEncoder encoder) {
    	final UserEntity originalUser = repository.findByUsername(username);
    	//matches메서드를 이용해 패스워드가 같은지 확인
    	if(originalUser != null && encoder.matches(password, originalUser.getPassword())) {
    		return originalUser;
    	}
        // UserRepository의 findByUsernameAndPassword 메서드를 사용하여 유저 정보를 조회한다.
        return null;
    }
}











