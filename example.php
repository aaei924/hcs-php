<?php
/**
* 라이브러리 사용 예시
*/
require 'HCSLib.php';

// 학교이름과 지역은 풀네임으로, 모든 인자는 String으로
$HCS = new HCS('한국고등학교', '홍길동', '040101', 'school', '서울특별시', '1234');

$HCS->findUser();
$HCS->selectUserGroup();
$res = HCS->registerServey();

if($res[0]['registerDtm'])
    echo '자가진단 완료';
