<?php
require __dir__.'/SEED_CBC_TransKey.php';

class TransKey
{
    public static string $delimiter = '$', $cookie = '';

    private static string $transkeyServlet, $baseurl;
    private static array $chars = [
        'lower' => ['1','2','3','4','5','6','7','8','9','0','q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m'],
        'upper' => ['1','2','3','4','5','6','7','8','9','0','Q','W','E','R','T','Y','U','I','O','P','A','S','D','F','G','H','J','K','L','Z','X','C','V','B','N','M'],
        'special' => ['`','~','!','@','#','$','%','^','&','*','(',')','-','_','=','+','[','{',']','}','\\','|',';',':','/','?',',','<','.','>','\'','"','+','-','*','/'],
        'number' => ['1','2','3','4','5','6','7','8','9','0']
    ];
    
    public $enc, $hmac, $keyIndex, $encSessionKey, $initTime, $stdntYn, $transkeyUuid, $allocationIndex, $token, $genSessionKey, $sessionKey, 
        $dummy, $keyData, $qwerty, $number, $keys, $lower, $upper, $special;

    public static array $keyboardTypes = [
        'common' => [
            'qwerty' => 'qwerty',
            'number' => 'number'
        ],
        'Mobile' => [
            'qwerty' => 'qwertyMobile',
            'number' => 'numberMobile'
        ]
    ];

    public function __construct(
        public string $password,
        string $baseurl,
        public string $keyboardType,
        public string $name,
        public string $inputName,
        public string $fieldType='password',
        public string $keyType='',
        public string $mode='common',
        $debug=false,
        $debugData=[]
    )
    {
        self::$transkeyServlet = $baseurl.'/transkeyServlet';
        self::$baseurl = $baseurl;
        $this->transkeyUuid = bin2hex(random_bytes(32));
        $this->keyboardType = self::$keyboardTypes[$mode][$keyboardType];
        $this->allocationIndex = strval(random_int(0, 0xffffffff));
        $this->token = self::getToken();
        $this->genSessionKey();
        $this->initTime = self::getInitTime();
        if($this->initTime)
            $this->getKeyIndex();
        
        if($this->keyIndex)
            $this->getDummy();
        else
            $this->allocation();
        
        if(!$this->getKeyInfo())
            $this->setSessionKey();
        
        $this->setKeyPos();
    }

    /**
     * get and set TK_requestToken value.
     */
    private static function getToken(): string
    {
        $getToken = self::fetch(self::$transkeyServlet.'?op=getToken');
        preg_match('/TK_requestToken=\'?([0-9a-fA-F]*)\'?;/', $getToken->body, $rTmatch);
        if(empty($rTmatch[1]))
            return '0';
        return $rTmatch[1];
    }

    /**
     * generate and encrypt session key.
     * @todo call $this->getToken()
     */
    private function genSessionKey(): void
    {
        $this->genSessionKey = bin2hex(random_bytes(16));
        $this->sessionKey = array_map('hexdec', str_split($this->genSessionKey));

        $certificate = self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'getPublicKey',
            'TK_requestToken' => $this->token
        ]))->body;
        if(!$certificate)
            $certificate = 'MIIDPTCCAiWgAwIBAgIJAOYjCX4wgWNSMA0GCSqGSIb3DQEBCwUAMGcxCzAJBgNVBAYTAktSMR0wGwYDVQQKExRSYW9uU2VjdXJlIENvLiwgTHRkLjEaMBgGA1UECxMRUXVhbGl0eSBBc3N1cmFuY2UxHTAbBgNVBAMTFFJhb25TZWN1cmUgQ28uLCBMdGQuMB4XDTE2MDUxNzA0MzAwMFoXDTQ2MDUxMDA0MzAwMFowOTELMAkGA1UEBhMCS1IxFDASBgNVBAoTC0N1bHR1cmVsYW5kMRQwEgYDVQQDEwtDdWx0dXJlbGFuZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOUUAmDna35jXlCBXMjE8Jf42xt7wM2L1B6j1ZkhzxsUQE4erfKV7G930giWbV23rXEn+PIeWbHNKAtKx7RIY0NB2+/l7eiYsLGUgDMcH8U+h6CKavIJ1XZbwjK9nTl4648rD4ZGrvxZyjPoPpv3Pb/GAKuf3ImDuj4/MtQffIY/WUTfaHP/iTJiWfqJMWIwhtmzNzTqIYJILdO/IWaKj4Or61OwtZfySmYnlA3NHeDZTjdmLbQHfmtPPw9Yi3lf3uZQvOlFpQA4q/1PM5liUGmVsXq3Pp6jYWDlIjeyirRpf1brIbUAswwLBte0wBqnWXtcCYvuuQ63EkJWmCutkTMCAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwDQYJKoZIhvcNAQELBQADggEBAE/tQugb2eHygCCUGtKJeib14bi9ZXwIZ8gmkJxPxbiGWA4Kaa3N9/ttUwFKbq5XBgRqGG8qZXcYKTbsHI3nBszek1ZZ/OZglPBRM+qGd4svVWbO/rlisKmyHyS0yzeUKAQAf6XzbWvO+PDADDGXJkcoPEpi/V1S884VS5e3k0wiiiBssSDSShHADXk/TCf4egnIxBkbwDL+9h3TqKwTERLmZirTbvNYpxaOSh0g6iA6kPeNff2V1+R0JXzxEHFeSBJtTbDBj2u0corNPeairiSVzjXTyEsaaUbfysd93cuDgruLIZw7h+d8nZaHYOK7m4oemVeXdi65LmT+7AbL51U=';
        $publicKey = openssl_pkey_get_public(openssl_x509_read(
            "-----BEGIN CERTIFICATE-----\n".
            $certificate.
            "\n-----END CERTIFICATE-----"
        ));
        openssl_public_encrypt($this->genSessionKey, $encrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        $this->encSessionKey = bin2hex($encrypted);
    }

    /**
     * set initiated time.
     */
    private static function getInitTime(): string|null
    {
        $getInitTime = self::fetch(self::$transkeyServlet.'?op=getInitTime')->body;

        preg_match('/ initTime=\'([0-9a-fA-F]*)\'/', $getInitTime, $iTmatch);
        //preg_match('/ decInitTime=\'([0-9]*)\'/', $getInitTime, $dITmatch);

        return $iTmatch[1];
        //$this->decInitTime = $dITmatch[1];
    }

    /**
     * get key index.
     * @todo call $this->setInitTime()
     * @todo call $this->getToken()
     */
    private function getKeyIndex(): void
    {
        $this->keyIndex = self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'getKeyIndex',
            'name' => $this->name,
            'keyboardType' => $this->keyboardType,
            'initTime' => $this->initTime,
            'keyType' => $this->keyType,
            'fieldType' => $this->fieldType,
            'inputName' => $this->inputName,
            'parentKeyboard' => 'false',
            'transkeyUuid' => $this->transkeyUuid,
            'exE2E' => 'false',
            'TK_requestToken' => $this->token,
            'isCrt' => 'false',
            'allocationIndex' => $this->allocationIndex,
            'keyIndex' => '',
            'talkBack' => 'true'
        ]))->body;
    }

    /**
     * get Dummy data from transkey.
     * @todo call $this->setInitTime()
     * @todo call $this->getToken()
     * @todo call $this->getKeyIndex()
     */
    private function getDummy(): void
    {
        $this->dummy = explode(',', self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'getDummy',
            'keyboardType' => $this->keyboardType,
            'fieldType' => $this->fieldType,
            'keyIndex' => $this->keyIndex,
            'name' => $this->name,
            'inputName' => $this->inputName,
            'transkeyUuid' => $this->transkeyUuid,
            'exE2E' => 'false',
            'isCrt' => 'false',
            'allocationIndex' => $this->allocationIndex,
            'initTime' => $this->initTime,
            'TK_requestToken' => $this->token,
            'keyType' => $this->keyType,
            'talkBack' => 'true',
            'dummy' => 'undefined'
        ]))->body);
    }
    
    private function allocation(): void
    {
        $this->dummy = explode(',', self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'allocation',
            'name' => $this->name,
            'keyType' => '',
            'keyboardType' => $this->keyboardType,
            'fieldType' => $this->fieldType,
            'inputName' => $this->inputName,
            'transkeyUuid' => $this->transkeyUuid,
            'TK_requestToken' => $this->token,
            'talkBack' => 'true',
            'dummy' => 'undefined'
        ]))->body);
    }

    /**
     * get key info.
     * @todo call $this->getToken()
     * @todo call $this->getKeyIndex()
     * $this->key
     */
    private function getKeyInfo(): void
    {
        $this->keyData = self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'getKeyInfo',
            'key' => $this->encSessionKey,
            'transkeyUuid' => $this->transkeyUuid,
            'useCert' => 'true',
            'TK_requestToken' => $this->token,
            'mode' => $this->mode
        ]))->body;
    }

    private function setSessionKey(): void
    {
        $this->keyData = self::fetch(self::$transkeyServlet, http_build_query([
            'op' => 'setSessionKey',
            'key' => $this->encSessionKey,
            'transkeyUuid' => $this->transkeyUuid,
            'useCert' => 'true',
            'TK_requestToken' => $this->token,
            'mode' => $this->mode
        ]))->body;
    }

    private function setKeyPos(): void
    {
        list($qwerty, $number) = explode('var '.self::$keyboardTypes[$this->mode]['number'].' = new Array();', $this->keyData);

        $this->qwerty = [];
        $this->number = [];

        foreach (array_slice(explode(self::$keyboardTypes[$this->mode]['qwerty'].'.push(key);', $qwerty), 0, -2) as $p){
            preg_match_all('/key\.addPoint\((\d+), (\d+)\);/', $p, $points);
            array_push($this->qwerty, [$points[1][0], $points[2][0]]);
        }

        foreach (array_slice(explode(self::$keyboardTypes[$this->mode]['number'].'.push(key);', $number), 0, -2) as $p){
            preg_match_all('/key\.addPoint\((\d+), (\d+)\);/', $p, $points);
            array_push($this->number, [$points[1][0], $points[2][0]]);
        }
        
        if(strpos($this->keyboardType, 'qwerty') !== false)
            $this->keys = $this->qwerty;
        else
            $this->keys = $this->number;
    }
    
    private function calcSkippedChars($chars): array
    {
        $keyidx = 0;
        $out = [];
        $cnt = count($chars)+count($this->dummy);
        for ($i=0; $i<$cnt; $i++){
            if (in_array($i, $this->dummy))
                array_push($out, '');
            else{
                array_push($out, $chars[$keyidx]);
                $keyidx += 1;
            }
        }
        return $out;
    }
    
    public function makeData(): void
    {
        if (strpos($this->keyboardType, 'qwerty') !== false){
            $this->lower = $this->calcSkippedChars(self::$chars['lower']);
            $this->upper = $this->calcSkippedChars(self::$chars['upper']);
            $this->special = $this->calcSkippedChars(self::$chars['special']);
        }
        
        $geos = [];
        $ctype = '';
        $this->enc = '';

        foreach (str_split($this->password) as $val){
            if (strpos($this->keyboardType, 'number') !== false){
                $curr = $this->dummy;
                $ctype = [];
            } elseif (in_array($val, self::$chars['lower'])) {
                $curr = $this->lower;
                $ctype = ['l'];
            } elseif (in_array($val, self::$chars['upper'])){
                $curr = $this->upper;
                $ctype = ['u'];
            } elseif(in_array($val, self::$chars['special'])) {
                $curr = $this->special;
                $ctype = ['s'];
            }
            
            // [ctype] + [x,y]
            list($x, $y) = $this->keys[array_search($val, $curr)];
            array_push($ctype, $x, $y);
            array_push($geos,$ctype);
        }
        
        if(strlen($this->initTime) > 0){
            foreach ($geos as $geo){
                $this->enc .= '$' . self::SeedEnc(implode(' ', $geo) . ' '.$this->initTime.' %', $this->sessionKey);
            }
        }else{
            foreach ($geos as $geo){
                $this->enc .= '$' . self::SeedEnc(implode(' ', $geo) . ' e'.chr(rand(0,100)), $this->sessionKey);
            }
        }
        $this->hmac = hash_hmac('sha256', $this->enc, $this->genSessionKey);
    }
    
    
    /**
     * encrypt data with SEED
     * @todo call $this->setInitTime()
     * @todo call $this->getToken()
     * @todo call $this->genSessionKey()
     * @todo call $this->getKeyIndex()
     * @todo call $this->getDummy()
     * $this->key
     * @return string
     */
    private static function SeedEnc(string $geo, array $sessionKey): string
    {
        $iv = [0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30];
        $tSize = 48;
        $inData = $outData = array_pad([], $tSize, 0);
        $geolen = strlen($geo);
        $encodedDataString = '';
        
        for($i=0; $i<$geolen; ++$i) {
            if(!is_numeric($geo[$i])) {
                $inData[$i] = mb_ord($geo[$i]);
            } else {
                $inData[$i] = intval($geo[$i]);
            }
        }
        
        SEED::SeedRoundKey($roundKey, $sessionKey);
        SEED::SeedEncryptCbc($roundKey, $iv, $inData, $tSize, $outData);

        for($i=0; $i<$tSize; $i++)
            $encodedDataString .= dechex($outData[$i]).',';
        
        return substr($encodedDataString, 0, strlen($encodedDataString) - 1);
    }

    private static function fetch($url, $body = null, $header=[], $method='POST')
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: '.self::$baseurl,
            'Referer: '.self::$baseurl,
            'Cookie: '.self::$cookie
        ] + $header);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        if($method == 'POST'){
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        
        $headers = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        return (object)['headers' => $headers, 'body' => $body];
    }

    private static function parseHeader(string $haystack): array
    {
        $headerset = explode('\r\n\r\n', $haystack);
        $res = [];
        foreach($headerset as $h) {
            $temp = explode(':', $h);
            $res[$temp[0]] .= $temp[1];
        }
        return $res;
    }
}
