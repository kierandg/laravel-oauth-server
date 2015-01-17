<?php
/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
return [
	'parameter_absent' => 'Tham số ":name" không tìm thấy.',
	'parameter_rejected' => 'Giá trị tham số không hợp lệ ":name" = ":value".',
	'timestamp_refused' => 'Giá trị timestamp ":value" gặp lỗi: trong tương lai, quá hạn, không hợp lệ.',
	'nonce_used' => 'Giá trị nonce ":value" đã được sử dụng.',
	'signature_method_rejected' => 'Giá trị của phương pháp chữ ký không hỗ trợ ":value", sử dụng "HMAC-SHA1".',
	'signature_invalid' => 'Chữ ký không hợp lệ ":value", signature base nhận được ":base".',
	'consumer_key_rejected' => 'Giá trị consumer key không hợp lệ hoặc không tìm thấy ":value".',
	'token_expired' => 'Token quá hạn ":value".', 'token_rejected' => 'Token không hợp lệ hoặc không tìm thấy ":value".',
	'version_rejected' => 'The version ":value" is not supported. You must specify 1.0 for the oauth_version parameter use "1.0" or "1.0a".',
	'not_authorized' => 'The consumer key/token passed was not valid or has expired.',
	'ip_rejected' => 'The IP address ":value" is not allowed.',
	'authorize_fail' => 'An error occurs during authorization.',
	'invalid_credentials' => 'Thông tin đăng nhập của username ":username" không hợp lệ.',
	'illegal_protocol' => 'Illegal protocol in redirect URI :uri',
	'unsupported_scheme' => 'Unsupported scheme type, expected http or https, got scheme :scheme'
];