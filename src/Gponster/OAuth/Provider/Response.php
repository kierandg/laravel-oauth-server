<?php

namespace Gponster\OAuth\Provider;

/**
 * Class OAuth Response
 * Edit from original library OAuth-PHP of Marc Worrell <marcw@pobox.com>
 * Helper class to generate XML response from result
 *
 * @author Vu Dang a.k.a Gponster <anhvudg@gmail.com>
 * @see http://code.google.com/p/oauth-php
 */
class Response {

	/**
	 * This is variable _xml description
	 */
	protected $xml = null;

	/**
	 * This is variable _status description
	 */
	protected $status = null;

	/**
	 * This is variable _error description
	 */
	protected $error = null;

	/**
	 * This is variable _error description
	 */
	protected $useAttrs = true;

	/* [ XML FORMAT CONFIG ] */

	/**
	 * Response XML tag name
	 */
	public static $tag = 'rsp';

	/**
	 * Response status attribute name
	 */
	public static $statAttr = 'stat';

	/**
	 * Response status success value
	 */
	public static $statOk = 'ok';

	/**
	 * Response status fail value
	 */
	public static $statFail = 'fail';

	/**
	 * Error XML tag name
	 */
	public static $errorTag = 'err';

	/**
	 * Error code attribute name
	 */
	public static $errorCodeAttr = 'code';

	/**
	 * Error message attribute name
	 */
	public static $errorMessageAttr = 'msg';

	/**
	 * This is method __construct
	 *
	 * @param array $response
	 *        	This is a description
	 * @param mixed $status
	 *        	This is a description
	 * @param array $useAttrs
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function __construct(array $response = array(), $status = true, $useAttrs = true) {
		$this->xml = simplexml_load_string(
			'<?xml version="1.0" encoding="utf-8"?><' . self::$tag . '></' . self::$tag . '>');

		$this->useAttrs = $useAttrs;
		$this->appendStatus($status);

		if(count($response) > 0) {
			$this->appendResponse($this->xml, $response);
		}
	}

	/**
	 * This is method appendStatus
	 *
	 * @param mixed $status
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function appendStatus($status = true) {
		if(is_null($this->status)) {
			if($this->useAttrs) {
				if($status === true) {
					$this->xml->addAttr(self::$statAttr, self::$statOk);
				} elseif($status === false) {
					$this->xml->addAttr(self::$statAttr, self::$statFail);
				} else {
					throw new \Exception('Invalid response status');
				}
			} else {
				if($status === true) {
					$this->xml->addChild(self::$statAttr, self::$statOk);
				} elseif($status === false) {
					$this->xml->addChild(self::$statAttr, self::$statFail);
				} else {
					throw new \Exception('Invalid response status');
				}
			}

			$this->status = $status;
		} else {
			throw\Exception('Response already has status');
		}
	}

	/**
	 * This is method appendResponse
	 *
	 * @param mixed $xml
	 *        	This is a description
	 * @param array $response
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function appendResponse($xml, array $response) {
		foreach($response as $key => $val) {
			if(is_array($val)) {
				$child = $xml->addChild($key);
				$this->appendResponse($child, $val);
			} else {
				if($this->useAttrs) {
					$xml->addAttr($key, $val);
				} else {
					$xml->addChild($key, $val);
				}
			}
		}
	}

	/**
	 * This is method appendError
	 *
	 * @param mixed $code
	 *        	This is a description
	 * @param mixed $message
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function appendError($code, $message) {
		if(is_null($this->error)) {
			$error = self::$errorTag;

			$this->xml->addChild($error);

			if($this->useAttrs) {
				$this->xml->$error->addAttr(self::$errorCodeAttr, $code);
				$this->xml->$error->addAttr(self::$errorMessageAttr, $message);
			} else {
				$this->xml->$error->addChild(self::$errorCodeAttr, $code);
				$this->xml->$error->addChild(self::$errorMessageAttr, $message);
			}

			$this->error = array(
				'code' => $code, 'msg' => $message
			);
		} else {
			throw\Exception('Response already has error');
		}
	}

	/**
	 * This is method get
	 *
	 * @param mixed $att
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function get($att = 'content', $stringOutput = true) {
		switch($att) {
			case 'content':
				if($stringOutput) {
					return $this->xml->asXml();
				} else {
					return $this->xml;
				}

			case 'error':
				if($stringOutput) {
					return $this->error->asXml();
				} else {
					return $this->error;
				}

			default:
				throw new \Exception('Not supported.');
		}
	}

	/**
	 * This is method xml
	 *
	 * @param mixed $att
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public function xml($att = 'content') {
		switch($att) {
			case 'content':
				return $this->xml;

			case 'error':
				return $this->error;

			default:
				throw new \Exception('Not supported.');
		}
	}

	/**
	 * This is method generate
	 *
	 * @param array $response
	 *        	This is a description
	 * @param mixed $status
	 *        	This is a description
	 * @param mixed $useAttrs
	 *        	This is a description
	 * @param mixed $stringOutput
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public static function generate(array $response = array(), $status = true, $useAttrs = true, $stringOutput = true, $lname = false,
		$iname = false) {
		$result = null;

		if($lname !== false && $iname !== false) {
			$result = new Response(array(
				$lname => array()
			), $status, $useAttrs);
			$xml = $result->xml->children();
			foreach($response as $i => $item) {
				$result->appendResponse($xml, array(
					$iname => $item
				));
			}
		} else {
			$result = new Response($response, $status, $useAttrs);
		}

		if($stringOutput) {
			return $result->xml->asXml();
		} else {
			return $result->xml;
		}
	}

	/**
	 * This is method plain
	 *
	 * @param array $response
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public static function plain(array $response) {
		foreach($response as $key => $val) {
			$content .= $key . '=' . $val . '&';
		}

		return substr($content, 0, strlen($content) - 1);
	}

	/**
	 * *
	 *
	 * @param mixed $code
	 *        	This is a description
	 * @param mixed $message
	 *        	This is a description
	 * @param mixed $useAttrs
	 *        	This is a description
	 * @param mixed $stringOutput
	 *        	This is a description
	 * @return mixed This is the return value description
	 */
	public static function error($code, $message, $useAttrs = true, $stringOutput = true) {
		$result = new Response(array(), false, $useAttrs);
		$result->appendError($code, $message);

		if($stringOutput) {
			return $result->xml->asXml();
		} else {
			return $result->xml;
		}
	}
}