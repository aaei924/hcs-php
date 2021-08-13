<?php
require 'db.php';
require 'Transkey.php';
use Raon;
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
    
    public static function requestAPI($url, $headers, array $data)
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
            $f = fopen('./nodejs/test.js', 'w');
            fwrite($f, 
            "const check = require('./check'); \n
            check('".$orgCode."','".$name."','".$region."','".$birthday."','".$password."','".$loginType."');");
            fclose($f);
            exec("node /var/www/html/covid/nodejs/test.js", $output, $return_var);
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
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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

        $password = new Raon($password);
        /* 
        {
            "raon": [
                {
                    "id":"password",
                    "enc":"$cc,bc,30,d5,8d,65,24,a3,72,9c,f4,7e,ae,d1,a2,dd$c1,1,a1,d9,8f,e6,f1,69,bf,42,b5,5f,fb,7f,b,90$58,b4,b8,24,42,81,e1,c5,66,ed,a,6d,57,5a,94,73$9a,61,6d,6a,44,f3,d3,c,6b,d,6b,81,55,4f,dc,d6$e9,ef,14,1d,c2,95,c8,f5,33,f0,d5,2b,ef,fe,9b,a5$59,8f,d4,af,c,cf,40,54,22,f6,fe,53,86,d3,8d,d0$c8,5f,24,3f,5c,63,2,af,3,3d,18,32,e5,1a,b9,b2",
                    "hmac":"11fe4d86a975406cf4dddba1e0731eee5f2554772339d973eeafb7c9a3b3b5d0",
                    "keyboardType":"number",
                    "keyIndex":"2b03a5e2f2fae5a30e7eb2e16de56ea5cf8abbc64184e563cf236984d7c6fc10a0bd292600db1077343d3a2183f29907adca7202420f643092ed5ed2aac0786094c10668785ed39d71484b26909e457f71685f8f1621b0867f3a9989482b09e9031952463a24ec3862d4b5577fe88abdedc9ae29edd3a33709ede571b924ebd3861252148f511f49633bcdadaa44da60666ad7479b7b1e5b0ed709e400c375f3eb22f5ad5e7c735213d2d113c53f661cf6907ff26298bde4f86fea16eed08d907d156e5ab0a6eb82a8e5ec53d37fcd515e1635edf94ac6b3dadc9f811f348ea09b7d2300bcc62bd72b1e5a9c9d09cc26a1b1a105b280209a244368ad9fcdd27a",
                    "fieldType":"password",
                    "seedKey":"22183421f6caefc5d5aab3236bc2b2e6c6ae84aa269136fe057bfd492b41277499efa449df6dbfabab109c0b367caeba641eaf6c50373b3e58e62625c8a03ad571396e4f6f68985d62e00b0a32df6aa98befb416e214d90bdbf30e7dd58e8e34af37ab229805e288a0159d15464f1f197e632d749bebcc28287b4d95f9b28d29e026e0314fb8978527af0b8d1ca3d4bda0ea05fccdaa9117dc3389813c8eed5a061d25844dc6657d3c7492ad87479515acd8565c5d56cc0acb6b83456b4dc74977715026de5a816b607070692a374f7c4f71451457199a2d5dd018aa7d18df25c7620de40a45551b2ec3ee1c90c746a370d8bdb24a61ac8e5c893c21a950c499",
                    "initTime":"7214012da3069d24e126ec5c",
                    "ExE2E":"false"
                }
            ]
        }
        */
        $data = [
            'password' => '{"raon":[{"id":"password","enc":"$2c,a1,fb,ad,f9,d6,79,55,7d,aa,e4,e,53,db,e0,d9$c6,ef,d0,b0,3d,53,8a,76,f2,8e,e7,b5,68,d3,e7,c1$76,60,30,f6,b0,72,48,53,44,7e,bc,1a,b8,6b,9a,4$6,a4,52,59,9,2c,33,2,85,1a,4f,c5,5a,8,40,26$f9,58,f6,85,f,c3,32,36,70,ab,bf,13,6a,53,7,44","hmac":"68624d75a567385818760e9c60039f1f7781729236fce9fde251b14af270a6b4","keyboardType":"number","keyIndex":"28296f90f3adb65c83fbd1371ed4035b9e9bf13d8c085286e280f2f4f0de4e36a0360da8360af175b97234ff0576df897821218865c28d02e555c2f54cb11619dcb6a7262b618aadfd5ce1c281e94f7888acff048e2be2ce28ab671bf672bd6f0daca03cc926c842f14311b88d11b079ef41e11828d058c06c9bf15fae6d064b3b3785d2fa00269cc5e8c9b716e05cd41a7dbccb14803c2f86f6f336dc2c2256e510969486b2b9372b4dca7f83c6723dac8373fe0a225c563e85baa3c78303febe9a70681dffdadc5f6312264ec2b26fa5dda303d3b6e2dca74c35a2a2ee1c9937eb64c37afbdb7f1c3bdd5a3ff473b67c7daf0007695b4b1a8a8481841a8d99","fieldType":"password","seedKey":"bc0f4c710e106bbe30adf8fbddd6a096d2b27c1d7563d08c396cad85c2b4938baccf9a49fd04fda30553bc6169d5ce001f634e539d5fd1e0669ac27412e4f0a4e107cb4a10845fce47e8a4f336a5400d556c401ce6d0043bdf2699ef686030c0d25c07e4e440247ce23089a726aaa6288e174b1966f3d4ba7c8584b0c50e748c05211e19a3d4bdf8ed84105312ec562133b9ac914d9eb055dd349e2be8dfff3f3ecad3df894036da3b8e80437ec412b0a3c225758394b6a729d312677ee1429f3eaf8a8a5a1f969c66bdbedb64c7bc6b8bc07b142845c3b37c516bab2ebe0bbcb2e383ce32fbee272340d91eb6b9f5df633532bc8e14dd97c0a2cf0d3a912d3c","initTime":"7214012da3069d24e126ee56","ExE2E":"false"}]}',//json_encode($password),
            'deviceUuid' => '',
            'makeSession' => true
        ];
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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
            'rspns08' => null,
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
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
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
        
        return self::requestAPI($url, $headers, $data);
    }
}
