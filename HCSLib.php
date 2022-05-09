<?php
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class HCS
{
    /**
    * 등교가 불가능하면(1, 3번 '예' 또는 2번 '양성) N, 아니면 Y
    */
    private static string $rspns00 = 'Y';
    
    /**
    * 1. 학생 본인이 코로나19 감염에 의심되는 아래의 임상증상이 있나요?: "1"=아니오, "2"=예
    */
    private static string $rspns01 = '1';
    
    /**
    * 3. 학생 본인 또는 동거인이 PCR 검사를 받고 그 결과를 기다리고 있나요?: "1"=아니오, "0"=예
    */
    private static string $rspns02 = '1';
    
    /**
    * 2. 학생은 오늘 신속항원검사(자가진단)를 실시했나요?: "1"=실시하지 않음, null=실시함
    */
    private static string|null $rspns03 = '1';
    
    /**
    * 2. 학생은 오늘 신속항원검사(자가진단)를 실시했나요?: null=실시하지 않음, "0"=음성, "1"=양성
    */
    private static string|null $rspns07 = null;
    
    /**
    * 내용없는 문항
    */
    private static $rspns04, $rspns05, $rspns06, $rspns08, $rspns09, $rspns10, $rspns11, $rspns12, $rspns13, $rspns14, $rspns15 = null;

    private static array $REGIONS = [
            'goe' => '경기',
            'sen' => '서울',
            'pen' => '부산',
            'sje' => '세종',
            'gen' => '광주',
            'ice' => '인천',
            'dge' => '대구',
            'dje' => '대전',
            'use' => '울산',
            'kwe' => '강원',
            'cbe' => '충북',
            'cne' => '충남',
            'jbe' => '전북',
            'jne' => '전남',
            'gbe' => '경북',
            'gne' => '경남',
            'jje' => '제주'
    ];
    
    public function __construct($orgName, $name, $birthday, $loginType, $region, $password)
    {
        $this->headers = [
            'Content-Type: application/json',
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $this->orgName = $orgName;
        $this->name = $name;
        $this->birthday = $birthday;
        $this->loginType = $loginType;
        $this->region = $region;
        $this->password = $password;
    }
    
    /**
    * RSA Encryption (RSA/ECB/PKCS1Padding)
    * @param string $text text to encrypt
    * @return string encrypted text
    */
    private static function RSAEncrypt(string $text): string
    {
        $key = PublicKeyLoader::load('-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA81dCnCKt0NVH7j5Oh2+SGgEU0aqi5u6sYXemouJWXOlZO3jqDsHYM1qfEjVvCOmeoMNFXYSXdNhflU7mjWP8jWUmkYIQ8o3FGqMzsMTNxr+bAp0cULWu9eYmycjJwWIxxB7vUwvpEUNicgW7v5nCwmF5HS33Hmn7yDzcfjfBs99K5xJEppHG0qc+q3YXxxPpwZNIRFn0Wtxt0Muh1U8avvWyw03uQ/wMBnzhwUC8T4G5NclLEWzOQExbQ4oDlZBv8BM/WxxuOyu0I8bDUDdutJOfREYRZBlazFHvRKNNQQD2qDfjRz484uFs7b5nykjaMB9k/EJAuHjJzGs9MMMWtQIDAQAB
-----END RSA PUBLIC KEY-----');
        $key = $key->withPadding(RSA::ENCRYPTION_PKCS1);
        return base64_encode($key->encrypt($text));
    }
    
    /**
    * send GET request with curl
    * @param string $url request URL
    * @param array $headers HTTP headers
    * @return array|null returns null when error
    */
    private static function requestGET($url, $headers =[], $decode=1): array|string|null
    { // cURL GET
        $ch = curl_init();                                 //curl 초기화
        curl_setopt($ch, CURLOPT_URL, $url);               //URL 지정하기
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);    //요청 결과를 문자열로 반환
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //header값 셋팅(없을시 삭제해도 무방함)
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);      //connection timeout 10초
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);   //원격 서버의 인증서가 유효한지 검사 안함
        $response = curl_exec($ch);
        curl_close($ch);
        
        return ($decode===1)?json_decode($response, true):$response;
    }
    
    /**
    * send POST request with curl
    * @param string $url request URL
    * @param array $headers HTTP headers
    * @param array $data form data to submit
    * @return array|null returns null when error
    */
    private static function requestPOST($url, $headers, array $data): array|null
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_URL, 'https://'.$url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //header값 셋팅(없을시 삭제해도 무방함)
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data,JSON_UNESCAPED_UNICODE)); //POST방식으로 넘길 데이터(JSON데이터)
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        $response = curl_exec($ch);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headers = substr($response, 0, $header_size);
        $body = substr($response, $header_size);
        curl_close($ch);
            
            return [json_decode($body, true), $headers];
    }
    
    public static function registerUser($orgCode, $name, $region, $birthday, $password, $loginType,$checksum)
    {
        global $db;
        // 자가진단 설정값 테스트
            $f = fopen('/home/pi/phs/hcs/test.js', 'w');
            fwrite($f, 
            "const check = require('./check'); \n
            check('".$orgCode."','".$name."','".$region."','".$birthday."','".$password."','".$loginType."');");
            fclose($f);
            exec("node /home/pi/phs/hcs/test.js", $output, $return_var);
            if(substr($output[0], 0, 6) !== 'Bearer'){
                return [false, $output[0]];
            }
        $a = $db->prepare("INSERT INTO `selfcheck`(name,orgCode,region,birthday,password,loginType,checksum) VALUES (?,?,?,?,?,?,?)");
        $a->execute([$name,$orgCode,$region,$birthday,$password,$loginType,$checksum]);
    }

    /**
     * hcs 1.9.5 update:
     * get search key
     * -----------------
     * hcs 1.9.10 update:
     * get crypted orgCode
     */
    public function getSchoolInfo(): void
    {
        $get = self::requestGET('https://hcs.eduro.go.kr/v2/searchSchool?orgName='.urlencode($this->orgName));
        
        foreach($get['schulList'] as $sc){
            if($sc['kraOrgNm'] == $this->orgName && $sc['lctnScNm'] == $this->region){
                $this->orgCode = $sc['orgCode'];
                $this->lctnScCode = $sc['lctnScCode'];
                $this->juOrgCode = $sc['juOrgCode'];
                $this->baseUrl = $sc['atptOfcdcConctUrl'];
                $this->searchKey = $get['key'];
            }else
                continue;
        }
        
        if(!isset($this->orgCode))
            die('school not found');
    }

    /**
     * find user data
     * -----------------
     * hcs 1.9.10 update:
     * change endpoint to /v3/
    */
    public function findUser(): void
    {
        require __DIR__.'/TransKey.php';
        $raon = new Transkey($this->password);
        
        $f = fopen('call_raon.js', 'w');

        fwrite($f, 
"const p = ".json_encode($raon->sessionKey)."
const q = '".$raon->initTime."'
const s = ".json_encode($raon->keys)."
const t = '".$this->password."'
const u = '".$raon->genSessionKey."'
const raon = require('./enc/getseed')
raon(t,p,q,s,u).then(r => console.log(r));");
        fclose($f);
        exec("node call_raon.js", $output, $return_var);
        
        $raon->enc = $output[0];
        $raon->finalize();

        $this->getSchoolInfo();
            
        $data = [
            'orgCode' => $this->orgCode,
            'name' => self::RSAEncrypt($this->name),
            'birthday' => self::RSAEncrypt($this->birthday),
            'loginType' => $this->loginType,
            'stdntPNo' => null,
            'password' => json_encode($raon->json()),
            'lctnScCode' => $this->lctnScCode,
            'deviceUuid' => '',
            'makeSession' => true,
            'searchKey' => $this->searchKey
        ];

        $res = self::requestPOST($this->baseUrl.'/v3/findUser', $this->headers, $data);
        $this->stdntYn = $res[0]['stdntYn'];
        $this->token = $res[0]['token'];
        $this->pInfAgrmYn = $res[0]['pInfAgrmYn'];
        $this->WAF = substr($res[1], strpos($res[1], 'WAF='), 37);
        $this->_JSESSIONID = substr($res[1], strpos($res[1], '_JSESSIONID='), 121);
        
        $this->debug = $res[0];
        //if($res[0]['isError'])
        //    throw new ErrorException($res[0]['statusCode'].'/'.$res[0]['errorCode'].':'.$res[0]['message']);
    }
    
    /**
    * get registered user list and change token
    */
    public function selectUserGroup(): void
    {
        $this->headers[4] = 'Authorization: '.$this->token;
        $this->headers[5] = 'Cookie: '.$this->WAF.$this->_JSESSIONID;
        
        $data = [];
        
        $res = self::requestPOST($this->baseUrl.'/v2/selectUserGroup', $this->headers, $data)[0];
        
        $this->token = $res[0]['token'];
        $this->userPNo = $res[0]['userPNo'];
        
        $this->headers[4] = 'Authorization: '.$this->token;
    }
    
    /**
    * get user details
    */
    public function getUserInfo(): void
    {
        $data = [
            'orgCode' => $this->juOrgCode,
            'userPNo' => $this->userPNo
        ];
        
        $res = self::requestPOST($this->baseUrl.'/v2/getUserInfo', $this->headers, $data);
    }
    
    /**
    * get hcs client version
    * @return string hcs client version
    */
    public static function getClientVersion(): string
    {
        file_get_contents('https://hcs.eduro.go.kr/');
        foreach($http_response_header as $header){
            if(str_starts_with($header, 'X-Client-Version')){
                $version = str_replace('X-Client-Version: ', '', $header);
                return $version;
            }
        }

        return 'Cannot find version';
    }
    
    /**
    * submit health check survey content
    * @return array|null returns null when error
    */
    public function registerServey(): array|null
    {
        $data = [
            'rspns00' => self::$rspns00,
            'rspns01' => self::$rspns01,
            'rspns02' => self::$rspns02,
            'rspns03' => self::$rspns03,
            'rspns04' => self::$rspns04,
            'rspns05' => self::$rspns05,
            'rspns06' => self::$rspns06,
            'rspns07' => self::$rspns07,
            'rspns08' => self::$rspns08,
            'rspns09' => self::$rspns09,
            'rspns10' => self::$rspns10,
            'rspns11' => self::$rspns11,
            'rspns12' => self::$rspns12,
            'rspns13' => self::$rspns13,
            'rspns14' => self::$rspns14,
            'rspns15' => self::$rspns15,
            'upperToken' => $this->token,
            'upperUserNameEncpt' => $this->name,
            'deviceUuid' => '',
            'clientVersion' => self::getClientVersion()
        ];
        
        return self::requestPOST($this->baseUrl.'/registerServey', $this->headers, $data);
    }
    
    /*
    public function searchSchool()
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$this->token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [
            'orgCode' => $orgCode,
            'userPNo' => $userPNo
        ]; 
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public function joinClassList()
    {
        
        $data = [];
        
        return self::requestPOST($this->region.'hcs.eduro.go.kr/joinClassList', $this->headers, $data);
    }
    
    public function join($token, $orgCode, $grade, $classNm, $classCode, $url)
    {
        $data = [
            'orgCode' => $this->orgCode,
            'grade' => $this->grade,
            'classNm' => $this->classNm,
            'classCode' => $this->classCode
        ];
        
        return self::requestPOST($this->region.'hcs.eduro.go.kr/join', $this->headers, $data);
    }
    
    public function joinDetail($data)
    {
        return self::requestPOST($this->region.'hcs.eduro.go.kr/joinDetail', $this->headers, $data);
    }*/
}
