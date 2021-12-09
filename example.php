<?php
require 'HCSLib.php';
$org = 'J100000000';
$reg = 'goe';
$name = '이름;
$birth = '000000';
$pass = '0000';

$fu = HCS::findUser($org, $name, $birth, 'school', $reg);
$vp = HCS::validatePassword($fu[0]['token'], $pass, $reg);

$WAF = substr($vp[1], strpos($vp[1], 'WAF='), 37);
$_JSESSIONID = substr($vp[1], strpos($vp[1], '_JSESSIONID='), 121);

$rs = HCS::registerServey($vp[0], $name, $reg, $WAF.$_JSESSIONID);

echo json_encode(['status' => 'Success', 'result' => $rs[0]]);
