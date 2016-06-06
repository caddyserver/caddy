<?php

ini_set("display_errors",1);

echo "resp: start\n";//.print_r($GLOBALS,1)."\n".print_r($_SERVER,1)."\n";

//echo print_r($_SERVER,1)."\n";

$length = 0;
$stat = "PASSED";

$ret = "[";

if (count($_POST) || count($_FILES)) {
	foreach($_POST as $key => $val) {
		$md5 = md5($val);
		
		if ($key != $md5) {
			$stat = "FAILED";
			echo "server:err ".$md5." != ".$key."\n";
		}
		
		$length += strlen($key) + strlen($val);
		
		$ret .= $key."(".strlen($key).") ";
	}
	$ret .= "] [";
	foreach ($_FILES as $k0 => $val) {

		$error = $val["error"];
		if ($error == UPLOAD_ERR_OK) {
			$tmp_name = $val["tmp_name"];
			$name = $val["name"];
			$datafile = "/tmp/test.go";
			move_uploaded_file($tmp_name, $datafile);
			$md5 = md5_file($datafile);

			if ($k0 != $md5) {
				$stat = "FAILED";
				echo "server:err ".$md5." != ".$key."\n";
			}      
			
			$length += strlen($k0) + filesize($datafile);
			
			unlink($datafile);
			$ret .= $k0."(".strlen($k0).") ";
		}
		else{
			$stat = "FAILED";
			echo "server:file err ".file_upload_error_message($error)."\n";
		}
	}
	$ret .= "]";
	echo "server:got data length " .$length."\n";
}


echo "-{$stat}-POST(".count($_POST).") FILE(".count($_FILES).")\n";

function file_upload_error_message($error_code) {
	switch ($error_code) { 
		case UPLOAD_ERR_INI_SIZE: 
		return 'The uploaded file exceeds the upload_max_filesize directive in php.ini'; 
		case UPLOAD_ERR_FORM_SIZE: 
		return 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form'; 
		case UPLOAD_ERR_PARTIAL: 
		return 'The uploaded file was only partially uploaded'; 
		case UPLOAD_ERR_NO_FILE: 
		return 'No file was uploaded'; 
		case UPLOAD_ERR_NO_TMP_DIR: 
		return 'Missing a temporary folder'; 
		case UPLOAD_ERR_CANT_WRITE: 
		return 'Failed to write file to disk'; 
		case UPLOAD_ERR_EXTENSION: 
		return 'File upload stopped by extension'; 
		default: 
		return 'Unknown upload error'; 
	} 
} 