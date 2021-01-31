package subway.auth.service;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;
import subway.auth.dto.TokenRequest;
import subway.auth.dto.TokenResponse;
import subway.auth.infrastructure.JwtTokenProvider;
import subway.common.exception.InvalidLoginException;
import subway.member.dao.MemberDao;
import subway.member.domain.Member;

@Service
public class AuthService {
    private final String TOKEN_REQUEST_EMPTY = "토큰에 대한 요청값이 비어 있습니다.";

    private JwtTokenProvider jwtTokenProvider;
    private MemberDao memberDao;

    public AuthService(JwtTokenProvider jwtTokenProvider, MemberDao memberDao) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.memberDao = memberDao;
    }

    private void checkValidLogin(TokenRequest tokenRequest) {
        if (tokenRequest.isEmpty()) {
            throw new IllegalStateException(TOKEN_REQUEST_EMPTY);
        }
        try {
            if (!memberDao.findByEmail(tokenRequest.getEmail())
                    .getPassword()
                    .equals(tokenRequest.getPassword())) {
                throw new InvalidLoginException(InvalidLoginException.EMAIL_PASSWORD_MISMATCH);
            }
        } catch (EmptyResultDataAccessException erdae) {
            throw new InvalidLoginException(InvalidLoginException.EMAIL_NOT_EXIST);
        }
    }

    public TokenResponse createToken(TokenRequest tokenRequest) {
        checkValidLogin(tokenRequest);
        String accessToken = jwtTokenProvider.createToken(tokenRequest.getEmail());
        return TokenResponse.of(accessToken);
    }

    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    public Member findMemberByToken(String token) {
        String email = jwtTokenProvider.getPayload(token);
        return memberDao.findByEmail(email);
    }
}
