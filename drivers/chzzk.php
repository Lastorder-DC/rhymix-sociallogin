<?php

namespace Rhymix\Modules\Sociallogin\Drivers;

class Chzzk extends Base
{
	const CHZZK_AUTH_URI = 'https://chzzk.naver.com/account-interlock';
	const CHZZK_API_URI = 'https://openapi.chzzk.naver.com/';

	/**
	 * @brief Auth 로그인 링크를 생성
	 * @param string $type
	 * @return string
	 */
	public function createAuthUrl(string $type = 'login'): string
	{
		$params = [
			'clientId'    => $this->config->chzzk_client_id,
			'redirectUri' => getNotEncodedFullUrl('', 'module', 'sociallogin', 'act', 'procSocialloginCallback', 'service', 'chzzk'),
			'state'       => $_SESSION['sociallogin_auth']['state'],
		];

		return self::CHZZK_AUTH_URI . '?' . http_build_query($params, '', '&');
	}

	/**
	 * @brief 인증 단계 (로그인 후 callback 처리) [실행 중단 에러를 출력할 수 있음]
	 * @return \BaseObject|void
	 */
	function authenticate()
	{
		// 위변조 체크
		if (!\Context::get('code') || \Context::get('state') !== $_SESSION['sociallogin_auth']['state'])
		{
			return new \BaseObject(-1, 'msg_invalid_request');
		}

		// API 요청 : 엑세스 토큰
		$token = $this->requestAPI('auth/v1/token', [
			'grantType'    => 'authorization_code',
			'clientId'     => $this->config->chzzk_client_id,
			'clientSecret' => $this->config->chzzk_client_secret,
			'code'         => \Context::get('code'),
			'state'        => \Context::get('state'),
		]);

		if (!$token || !isset($token['content']['accessToken']))
		{
			return new \BaseObject(-1, 'msg_errer_api_connect');
		}

		// 토큰 삽입
		$accessValue['access'] = $token['content']['accessToken'];
		$accessValue['refresh'] = $token['content']['refreshToken'];

		\Rhymix\Modules\Sociallogin\Base::setDriverAuthData('chzzk', 'token', $accessValue);

		return new \BaseObject();
	}

	/**
	 * @brief 인증 후 프로필을 가져옴.
	 * @return \BaseObject
	 */
	function getSNSUserInfo()
	{
		// 토큰 체크
		$serviceAccessData = \Rhymix\Modules\Sociallogin\Base::getDriverAuthData('chzzk');
		if (!$serviceAccessData->token['access'])
		{
			return new \BaseObject(-1, 'msg_errer_api_connect');
		}

		// API 요청 : 유저 정보
		$headers = [
			'Authorization' => 'Bearer ' . $serviceAccessData->token['access'],
		];
		$profile = $this->requestAPI('open/v1/users/me', [], $headers, 'GET');

		if (!$profile || !isset($profile['content']['channelId']))
		{
			return new \BaseObject(-1, 'msg_errer_api_connect');
		}

		$channelId = $profile['content']['channelId'];
		$channelName = $profile['content']['channelName'];

		// 프로필 이미지를 위해 채널 정보 조회 (Client 인증)
		$channelImageUrl = '';
		$channelHeaders = [
			'Client-Id'     => $this->config->chzzk_client_id,
			'Client-Secret' => $this->config->chzzk_client_secret,
		];
		$channelInfo = $this->requestAPI('open/v1/channels?channelIds=' . $channelId, [], $channelHeaders, 'GET');

		if ($channelInfo && isset($channelInfo['content']['data']) && !empty($channelInfo['content']['data']))
		{
			$channelImageUrl = $channelInfo['content']['data'][0]['channelImageUrl'] ?? '';
		}

		$profileValue['sns_id'] = $channelId;
		$profileValue['email_address'] = $channelId . '@chzzk';
		$profileValue['user_name'] = $channelName;
		$profileValue['profile_image'] = $channelImageUrl;
		$profileValue['url'] = 'https://chzzk.naver.com/' . $channelId;
		$profileValue['etc'] = $profile['content'];

		\Rhymix\Modules\Sociallogin\Base::setDriverAuthData('chzzk', 'profile', $profileValue);

		return new \BaseObject();
	}

	/**
	 * @brief 토큰 파기 (SNS 해제 또는 회원 삭제시 실행)
	 */
	function revokeToken(string $access_token = '')
	{
		if (!$access_token)
		{
			return;
		}

		$this->requestAPI('auth/v1/token/revoke', [
			'clientId'      => $this->config->chzzk_client_id,
			'clientSecret'  => $this->config->chzzk_client_secret,
			'token'         => $access_token,
			'tokenTypeHint' => 'access_token',
		]);
	}

	/**
	 * @brief 토큰 새로고침 (로그인 지속이 되어 토큰 만료가 될 경우를 대비)
	 */
	public function refreshToken(string $refresh_token = ''): array
	{
		if (!$refresh_token)
		{
			return [];
		}

		$token = $this->requestAPI('auth/v1/token', [
			'grantType'    => 'refresh_token',
			'refreshToken' => $refresh_token,
			'clientId'     => $this->config->chzzk_client_id,
			'clientSecret' => $this->config->chzzk_client_secret,
		]);

		$returnTokenData = [];
		if ($token && isset($token['content']['accessToken']))
		{
			$returnTokenData['access'] = $token['content']['accessToken'];
			$returnTokenData['refresh'] = $token['content']['refreshToken'];
		}
		return $returnTokenData;
	}

	function getProfileImage()
	{
		return \Rhymix\Modules\Sociallogin\Base::getDriverAuthData('chzzk')->profile['profile_image'] ?: false;
	}

	/**
	 * @brief API 요청
	 */
	function requestAPI($url, $post = [], $headers = [], $method = 'POST')
	{
		if ($method === 'POST' && !empty($post))
		{
			$headers['Content-Type'] = 'application/json';
			$resource = \FileHandler::getRemoteResource(self::CHZZK_API_URI . $url, json_encode($post), 3, 'POST', 'application/json', $headers);
		}
		else
		{
			$resource = \FileHandler::getRemoteResource(self::CHZZK_API_URI . $url, null, 3, 'GET', null, $headers);
		}

		return json_decode($resource, true);
	}
}
