<?php
require 'db.php';
require 'Transkey.php';
require '/home/pi/phs/vendor/autoload.php';
use Raon;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class HCS
{
    public static $URL = [
        'ENCRYPT' => 'https://cov.prws.kr/api/encrypt.php'
    ];
    
    public static $REGIONS = [
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
    
    public static function RSAEncrypt($text)
    {
        $key = PublicKeyLoader::load('-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA81dCnCKt0NVH7j5Oh2+SGgEU0aqi5u6sYXemouJWXOlZO3jqDsHYM1qfEjVvCOmeoMNFXYSXdNhflU7mjWP8jWUmkYIQ8o3FGqMzsMTNxr+bAp0cULWu9eYmycjJwWIxxB7vUwvpEUNicgW7v5nCwmF5HS33Hmn7yDzcfjfBs99K5xJEppHG0qc+q3YXxxPpwZNIRFn0Wtxt0Muh1U8avvWyw03uQ/wMBnzhwUC8T4G5NclLEWzOQExbQ4oDlZBv8BM/WxxuOyu0I8bDUDdutJOfREYRZBlazFHvRKNNQQD2qDfjRz484uFs7b5nykjaMB9k/EJAuHjJzGs9MMMWtQIDAQAB
-----END RSA PUBLIC KEY-----');
        $key = $key->withPadding(RSA::ENCRYPTION_PKCS1);
        return base64_encode($key->encrypt($text));
    }
    
    public static function requestGET($url, $headers =array())
        { // cURL GET
            $ch = curl_init();                                 //curl 초기화
            curl_setopt($ch, CURLOPT_URL, $url);               //URL 지정하기
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);    //요청 결과를 문자열로 반환
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //header값 셋팅(없을시 삭제해도 무방함)
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);      //connection timeout 10초
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);   //원격 서버의 인증서가 유효한지 검사 안함
            $response = curl_exec($ch);
            curl_close($ch);
         
            return json_decode($response, true);
        }
    
    public static function requestPOST($url, $headers, array $data)
    {
        $ch = curl_init();
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //header값 셋팅(없을시 삭제해도 무방함)
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data,JSON_UNESCAPED_UNICODE)); //POST방식으로 넘길 데이터(JSON데이터)
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            $response = curl_exec($ch);
            curl_close($ch);
         
            return json_decode($response, true);
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
    
    public static function findUser($orgCode, $name, $birthday, $loginType, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [
            'orgCode' => $orgCode,
            'name' => $name,
            'birthday' => $birthday,
            'loginType' => $loginType,
            'stdntPNo' => null
        ];
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function hasPassword($token, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function validatePassword($token, $password, $url)
    {
        $headers = [
            'Content-Type: application/json;charset=utf-8',
            'Authorization: '.$token,
            'X-Requested-With: XMLHttpRequest',
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];

        //$raon = Transkey::inputFillEncData($HTML);
        $mtk = new TransKey("https://hcs.eduro.go.kr/transkeyServlet");
        $pw_pad = $mtk->new_keypad('number', 'password', 'password', 'password');
        $encrypted = $pw_pad->encrypt_password($password);
        $hm = $mtk->hmac_digest($encrypted);
        $f = fopen('/home/pi/phs/hcs/call_raon.js', 'w');
            fwrite($f, 
            "const p = '".$password."'
const raon = require('./enc/raon')
raon(p).then(r => console.log(r));");
            fclose($f);
            exec("node /home/pi/phs/hcs/call_raon.js", $output, $return_var);
       // $password = new Raon($password);
        $data = [
            'password' => $output[0],
            'deviceUuid' => '',
            'makeSession' => true
        ];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function selectUserGroup($token, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function getUserInfo($token, $orgCode, $userPNo, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
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
    
    public static function registerServey($token, $username, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/',
            'Sec-Fetch-Mode: cors',
            'Sec-Fetch-Site: same-site'
        ];
        
        $data = [
            'rspns00' => 'Y',
            'rspns01' => '1',
            'rspns02' => '1',
            'rspns03' => null,
            'rspns04' => null,
            'rspns05' => null,
            'rspns06' => null,
            'rspns07' => null,
            'rspns08' => '0',
            'rspns09' => '0',
            'rspns10' => null,
            'rspns11' => null,
            'rspns12' => null,
            'rspns13' => null,
            'rspns14' => null,
            'rspns15' => null,
            'upperToken' => $token,
            'upperUserNameEncpt' => $username,
            'deviceUuid' => ''
        ];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function searchSchool($loginType, $orgName, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
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
    
    public static function joinClassList($token, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function join($token, $orgCode, $grade, $classNm, $classCode, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [
            'orgCode' => $orgCode,
            'grade' => $grade,
            'classNm' => $classNm,
            'classCode' => $classCode,
            'userPNo' => $userPNo
        ];
        
        return self::requestPOST($url, $headers, $data);
    }
    
    public static function joinDetail($token, $orgCode, $userPNo, $url)
    {
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token,
            'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Mobile/13B143',
            'Origin: https://hcs.eduro.go.kr',
            'Referer: https://hcs.eduro.go.kr/'
        ];
        
        $data = [
            'orgCode' => $orgCode,
            'grade' => $grade,
            'classCode' => $classCode,
            'name' => $name,
            'userPNo' => $userPNo
        ];
        
        return self::requestPOST($url, $headers, $data);
    }
}
