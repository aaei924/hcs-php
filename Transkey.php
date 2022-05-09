<?php
require __dir__.'/KISA_SEED_CBC.php';
class TransKey
{
    private static string $delimiter = '$';
    private static string $token;
    private static array $keysXY = [
        [125, 27], [165, 27], [165, 67], [165, 107],
        [165, 147], [125, 147], [85, 147], [45, 147],
        [45, 107], [45, 67], [45, 27], [85, 27]
    ];

    public function __construct(string $password, $debug=false, $debugData=[])
    {
        $transkeyServlet = 'https://hcs.eduro.go.kr/transkeyServlet';

        // requestToken
        $getToken = self::fetch($transkeyServlet.'?op=getToken');
        preg_match('/TK_requestToken=\'?([0-9a-fA-F]*)\'?;/', $getToken, $rTmatch);
        self::$token = $rTmatch[1];

        // session key
        $this->genSessionKey = bin2hex(random_bytes(16));
        $this->sessionKey = array_map('hexdec', str_split($this->genSessionKey));

        $certificate = self::fetch($transkeyServlet, http_build_query([
            'op' => 'getPublicKey',
            'TK_requestToken' => self::$token
        ]));
        $publicKey = openssl_pkey_get_public(openssl_x509_read(
            "-----BEGIN CERTIFICATE-----\n".
            $certificate.
            "\n-----END CERTIFICATE-----"
        ));
        
        openssl_public_encrypt($this->genSessionKey, $encrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        $this->encSessionKey = bin2hex($encrypted);
        
        // get initTime
        $getInitTime = self::fetch($transkeyServlet.'?op=getInitTime');
        preg_match('/ initTime=\'([0-9a-fA-F]*)\'/', $getInitTime, $iTmatch);
        //preg_match('/ decInitTime=\'([0-9]*)\'/', $getInitTime, $dITmatch);
        $this->initTime = $iTmatch[1];
        //$this->decInitTime = $dITmatch[1];

        $this->keyIndex = self::fetch($transkeyServlet, http_build_query([
            'op' => 'getKeyIndex',
            'name' => 'password',
            'keyboardType' => 'number',
            'initTime' => $this->initTime
        /*
            'keyType' => 'single',
            'fieldType' => 'password',
            'inputName' => 'password',
            'parentKeyboard' => 'false',
            'transkeyUuid' => $this->uuid,
            'exE2E' => 'false',
            'TK_requestToken' => self::$token,
            'isCrt' => 'false',
            'allocationIndex' => '3011907012',
            'keyIndex' => '',
            'talkBack' => 'true'
        */
        ]));

        $this->keys = explode(',', self::fetch($transkeyServlet, http_build_query([
            'op' => 'getDummy',
            'keyboardType' => 'number',
            'fieldType' => 'password',
            'keyIndex' => $this->keyIndex,
            'talkBack' => 'true'
        /*
            'name' => $name,
            'keyType' => 'single',
            'inputName' => $inputName,
            'transkeyUuid' => $this->uuid,
            'exE2E' => 'false',
            'isCrt' => 'false',
            'allocationIndex' => '3011907012',
            'initTime' => $this->initTime,
            'TK_requestToken' => self::$token,
            'dummy' => 'undefined',
        */
        ])));

        $this->enc = implode('', array_map(function($n) {
            list($x, $y) = self::$keysXY[array_search($n, $this->keys)];
            return self::$delimiter . self::SeedEnc($x.' '.$y, $this->sessionKey, $this->initTime);
        }, str_split($password)));
        
        for ($j=4; $j<128; $j++) {
            $this->enc .= self::$delimiter . self::SeedEnc('# 0 0', $this->sessionKey, $this->initTime);
        }
        
        // get keyinfo
        /*
        $this->keyInfo = self::fetch($transkeyServlet, http_build_query([
            'op' => 'getKeyInfo',
            'key' => $this->key,
            'transkeyUuid' => $this->uuid,
            'useCert' => 'true',
            'TK_requestToken' => self::$token,
            'mode' => 'common'
        ]));
        */
    }

    public function finalize()
    {
        $this->hmac = hash_hmac('sha256', $this->enc, $this->genSessionKey);
    }

    private static $encDelimiter = ',';
    public static function SeedEnc(string $geo, array $sessionKey, string $initTime)
    {
        $iv = ['4d', '6f', '62', '69', '6c', '65', '54', '72', '61', '6e', '73', '4b', '65', '79', '31', '30'];
        $tSize = 48;
        $inData = array_pad([], $tSize, 0);
        $geolen = strlen($geo);
        
        for($i=0; $i<$geolen; ++$i) {
            if(in_array($geo[$i], ['l', 'u', '#', ' '])) {
                $inData[$i] = mb_ord($geo[$i]);
            } else {
                $inData[$i] = $geo[$i];
            }
        }

        $inData[++$i] = 32;
        $iTlen = strlen($initTime);
        for ($k=0; $k<$iTlen; ++$k) {
            if(preg_match('/^[a-z]$/', $initTime[$k]))
                $inData[$i++] = mb_ord($initTime[$k]); // Alphabet
            else
                $inData[$i++] = $initTime[$k]; // Number
        }

        $inData[$i++] = 32;
        $inData[$i++] = 37;
        
        $iv = array_map('hexdec', $iv);
	
        
        $roundKey = KISA_SEED_CBC::SeedRoundKey(KISA_ENC_DEC::KISA_ENCRYPT, $sessionKey, $iv);
        $outData = KISA_SEED_CBC::SEED_CBC_Encrypt($roundKey, $inData, 0, $tSize);

		$encodedData = array_pad([], $tSize, 0);
		$encodedDataString = "";

		for ($k = 0; $k < $tSize; $k++) {
			if (self::$encDelimiter === null)
				$encodedData[$k] = dechex(intval($outData[$k]));
			else
				$encodedDataString .= dechex(intval($outData[$k])) . self::$encDelimiter;
		}

		if (self::$encDelimiter === null)
			return $encodedData;
		else
			return substr($encodedDataString, 0, strlen($encodedDataString) - 1);
    }
    
    public function json(): array
    {
        return [
            'raon' => [[
                'id' => 'password',
                'enc' => $this->enc,
                'hmac' => $this->hmac,
                'keyboardType' => 'number',
                'keyIndex' => $this->keyIndex,
                'fieldType' => 'password',
                'seedKey' => $this->encSessionKey,
                //'initTime' => $this->initTime,
                //'ExE2E' => 'false'
            ]]
        ];
    }

    private static function fetch($url, $body = null)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ]);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }
}
