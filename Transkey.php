<?php
class Raon
{
    $this->delimiter = '$';
    $this->transkeyServlet = 'https://hcs.eduro.go.kr/transkeyServlet';
    
    public function __construct($password)
    {
        $publicKey = [
            'n' => '00e58d6a1c010cf703505cb454520876b0e2a2e0c732652b18824d367c3a7b420ad56e148c84484ff48e1efcfc4534fe1e8773f57e07b5bb0f9880349978db85c2bbbc39ccf2ef899dd8ae56fa6401b4f3a1eace450cda1b0412752e4a7b163d85e35a3d87a8f50588f336bcfde8f10c616998f8475b54e139a5f62b875ebb46a4bd21c0bac7dacce227bfe6b08da53849118c61958dd17b5cedd96b898cfd0b6cabcceaa971c634456530c5cc0a7a99152e34abd2857387cc6cbddf6c393d035da9ac960232ae5f7dcc4f62d776235d46076a871e79d5527e40e74a8199f03bd1b342e415c3c647afb45820fa270e871379b183bde974ed13e1bd8b467f0d1729',
            'k' => 256,
            'e' => '010001'
        ];
        $getInitTime = file_get_contents('https://hcs.eduro.go.kr/transkeyServlet?op=getInitTime');
        $initTime = preg_match('/var initTime='(.*)';/', $getInitTime)[1];
        $genSessionKey = bin2hex(random_bytes(16));
        $sessionKey = array_map(explode('', $genSessionKey), fn($char) => '0x0'.$char);
        $encSessionKey = self::encrypt($genSessionKey, $publicKey);
        $keyIndex = file_get_contents($this->transkeyServlet, false, stream_context_create([
  'http'=> [
      'method'=>"POST",
      'header'=>"Content-Type: application/x-www-form-urlencoded\r\n",
      'content' => 'op=getKeyIndex&name=password&keyboardType=number&initTime='.$initTime
  ]
]));
        $dummy = file_get_contents($this->transkeyServlet, false, stream_context_create([
  'http'=> [
      'method'=>"POST",
      'header'=>"Content-Type: application/x-www-form-urlencoded\r\n",
      'content' => 'op=getDummy&keyboardType=number&fieldType=password&keyIndex='.$keyIndex.'&talkBack=true'
  ]
]));
        $keysXY = [
            [125, 27], [165, 27], [165, 67], [165, 107],
            [165, 147], [125, 147], [85, 147], [45, 147],
            [45, 107], [45, 67], [45, 27], [85, 27]
        ];
        $keys = explode(',', $dummy);
        $enc = implode('', array_map(explode('', $password), function($n) {
            list($x, $y) = $keysXY(array_search($n, $keys));
            return $this->delimiter.self::SeedEnc($x.' '.$y, $sessionKey, $initTime);
        }));
        for ($j = 4; $j < 128; ++$j) {
            $enc .= $this->delimiter.self::SeedEnc('# 0 0', $sessionKey, $initTime);
        }
        $hmac = hash_hmac('sha256', $enc, $genSessionKey);
        return [
            'raon' => [[
                'id' => 'password',
                'enc' => $enc,
                'hmac' => $hmac,
                'keyboardType' => 'number',
                'keyIndex' => $keyIndex,
                'fieldType' => 'password',
                'seedKey' => $encSessionKey
            ]]
        ];
    }
    
    public static function pack($source)
    {
        $temp = '';
        for ($i=0; $i<strlen($source); $i += 2){
            $temp .= chr(intval(substr($source, $i, $i+2),16))
        }
        return $temp;
    }
    
    public static function xor($a,$b)
    {
        $length = min(strlen($a), strlen($b));
        $temp = '';
        for($i=0; $i<$length; $i++) {
            $temp .= chr(ord($a[$i]) ^ ord($b[$i]));
        }
        $length = max(strlen($a), strlen($b)) - $length;
        for($i=0; $i<$length; $i++) {
            $temp .= "\x00"
        }
        return $temp;
    }
    
    public static function BigInteger($a, $b, $c)
    {
    }
    
    public static function encrypt($plaintext, $publicKey)
    {
        list($k, $e, $n) = $publicKey;
        $temp = [];
        //SecureRandom.nextBytes(temp)
        
        
    }
}
class TransKey
{
    public function __construct($password)
    {
        $this->encDelimiter = ',';
        $this->delimiter = '$';
        $this->g_tk_seed = '';
        $this->g_tk_seded = 0;
        $this->g_tk_pool = 10325476;
        $this->g_tk_x = '';
        $pKey = [
            'n' => '00e58d6a1c010cf703505cb454520876b0e2a2e0c732652b18824d367c3a7b420ad56e148c84484ff48e1efcfc4534fe1e8773f57e07b5bb0f9880349978db85c2bbbc39ccf2ef899dd8ae56fa6401b4f3a1eace450cda1b0412752e4a7b163d85e35a3d87a8f50588f336bcfde8f10c616998f8475b54e139a5f62b875ebb46a4bd21c0bac7dacce227bfe6b08da53849118c61958dd17b5cedd96b898cfd0b6cabcceaa971c634456530c5cc0a7a99152e34abd2857387cc6cbddf6c393d035da9ac960232ae5f7dcc4f62d776235d46076a871e79d5527e40e74a8199f03bd1b342e415c3c647afb45820fa270e871379b183bde974ed13e1bd8b467f0d1729',
            'k' => 256,
            'e' => '010001'
        ];
        
        $initTime = file_get_contents('https://hcs.eduro.go.kr/transkeyServlet?op=getInitTime');
        $decInitTime = str_replace("'", '', explode('=', explode(';', $initTime)[0])[1]);
        $genSessionKey = $this->GenerateKey(128);
        $sessionKey = array_fill(0,16, null);
        for($i=0; $i < 16; ++$i){
            $sessionKey[$i] = hexdec('0x0' + substr($genSessionKey, $i, 1));
        }
        $encSessionKey = $this->phpbb_encrypt2048($genSessionKey, $)
    }
    
    public function S4()
    {
        $seed = date('s');
        return $this->tk_getrnd_hex(2);
    }
    
    public function GenerateKey($bit)
    {
        $cnt = $bit / (8 * 4);
        $key = '';
        for($i=0; $i<$cnt; ++$i){
            $key .= $this->S4();
        }
        return $key;
    }
    
    public function tk_getrnd_int()
    {
        return $this->tk_getrnd_int();
    }
    
    public function tk_entropy_pool($value)
    {
        $this->g_tk_pool .= $value;
    }
    
    public function tk_get_entropy()
    {
        $Xseed1 = date('s');
        $Xseed2 = date('v');
        return strval($Xseed2).'10802419201080'.strval($Xseed1).$this->g_tk_pool.strval($Xseed2);
    }
    
    public function tk_sh1prng()
    {
        if(!$this->g_tk_seeded) {
            $this->g_tk_seed = hash('sha256', $this->tk_get_entropy());
            $this->g_tk_seeded = 1;
        }
        $XSEEDj = date('s').$date('v');
        $xval = $XSEEDj.$this->g_tk_seed.$this->g_tk_x.'1';
        $this->g_tk_x = hash('sha256', $xval);
        return $this->g_tk_x;
    }
    
    public function tk_getrnd_hex($length)
    {
        $rand = '';
        if($length < 20) {
            $rand = $this->tk_sh1prng();
            $rand = substr($rand, 0, $length * 2);
            return $rand;
        } else {
            $_l = floor($length / 20);
            for($i=0; $i<$_l; ++$i){
                $rand .= $this->tk_sh1prng();
            }
            if($length % 20) {
                $rand_tmp = $this->tk_sh1prng();
                $rand .= substr($rand_tmp, 0, ($length % 20) * 2);
            }
        }
        return $rand;
    }
    
    public function tk_getrnd_int() {
        $rand_int = 0;
        $rand = $this->tk_sh1prng();
        $rand = substr($rand, 0, 8);
        $rand_int = dechex(floor($rand));
        return $rand_int;
    }
    
    public function tk_sha1($msg)
    {
        function rotate_left($n, $s){
            $t4 = ($n << $s) | ($n >>> (32 - $s));
            return $t4
        }
        
        function lsb_hex($val){
            $str = '';
            for($i=0; $i <= $6; $i += 2) {
                $vh = ($val >>> ($i * 4 + 4)) & 0x0f;
                $vl = ($val >>> ($i * 4)) & 0x0f;
                $str .= strval(hexdec($vh)).strval(hexdec($vl));
            }
            return $str;
        }
        
        function cvt_hex($val) {
            $str = '';
            for($i = 7; $i >= 0; --$i){
                $v = ($val >>> ($i * 4)) & 0x0f;
                $str = strval(hexdec($v));
            }
            return $str;
        }
        
        function Utf8Encode($string) {
            $utftext = '';
            $_len = iconv_strlen($string);
            for($n = 0; $n < $_len; ++$n) {
                $c = mb_ord(substr())
            }
        }
    }
}
