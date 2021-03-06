<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'static/vendor/autoload.php';

function restructureArray(array $arr) {
	$result = array();
	foreach ($arr as $key => $value) {
		for ($i = 0; $i < count($value); $i++) {
			$result[$i][$key] = $value[$i];
		}
	}
	return $result;
}

function responseHandler($status, $msg) {
	if ($status) {
		http_response_code(200);
		$response = [
			"code" => 200,
			"message" => $msg
		];
		echo json_encode($response);
	} else {
		http_response_code(500);
		$response = [
			"code" => 500,
			"message" => $msg
		];
		echo json_encode($response);
	}
	exit;
}

$name = $argv[1];
$email = $argv[2];
$phone = $argv[3];
$message = $argv[4];
$files = [];
if (!empty($argv[5]['file'])) {
	$files = restructureArray($argv[5]['file']);
}

$secret="SECRET";
$response=$argv[6];

$html = '
<!DOCTYPE html>
<html lang="en">
<head>
	<style>
		body {
			font-family: ;
			background-color: #f0f3f4;
			margin: 0 auto !important;
			padding: 0 !important;
			height: 100% !important;
			width: 100% !important;
		}

		#users {
			border-collapse: collapse;
			width: 100%;
		}

		#users td, #users th {
			border: 1px solid #ddd;
			padding: 8px;
		}

		#users tr:nth-child(even) {
			background-color: #f2f2f2;
		}

		#users tr:hover {
			background-color: #ddd;
		}

		#users th {
			padding-top: 12px;
			padding-bottom: 12px;
			text-align: left;
			background-color: #db0000;
			color: white;
		}

	</style>
</head>
<body>
';
$html .='
<table style="width: 100%; background-color: #f0f3f4; padding: 20px">
	<tr>
		<td>
			<table style="width: 640px; margin: 0px auto;">
				<tr>
					<td>
						<table>
							<tr>
								<td colspan="2">
									<p>
										New message from <b>'.$name.'</b>
									</p>
								</td>
							</tr>
						</table>
						<table id="users">
							<tr>
								<th>Name</th>
								<th>'.$name.'</th>
							</tr>
							<tr>
								<th>Email</th>
								<th>'.$email.'</th>
							</tr>
							<tr>
								<th>Phone</th>
								<th>'.$phone.'</th>
							</tr>
							<tr>
								<th>Message</th>
								<th>'.$message.'</th>
							</tr>
						</table>
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>
</body>
</html>
';

// $headers = 'MIME-Version: 1.0' . "\r\n";
// $headers .= 'Content-type:text/html;charset=UTF-8' . "\r\n";


// if (mail('ciaodejan@gmail.com', "New message at mindempathy.net from ".$name, $html, $headers)) {
// 	echo '<pre>';print_r("Message sent successfully!");echo '<pre>';
// } else {
// 	echo '<pre>';print_r("Failed to send message.");echo '<pre>';
// }

$mail = new PHPMailer(true);

$verify=file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$secret}&response={$response}");
$captcha_success=json_decode($verify);
if ($captcha_success->success==false) {
	responseHandler(false, 'Message could not be sent. Captcha Error: verification not successful.');
}
else if ($captcha_success->success==true) {
	try {
		//Server settings
	    $mail->isSMTP();                                            // Send using SMTP
	    $mail->Host       = 'smtp.zoho.eu';                    // Set the SMTP server to send through
	    $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
	    $mail->Username   = 'moreondt@gmail.com';                     // SMTP username
	    $mail->Password   = 'Dragana*7';                               // SMTP password
	    $mail->SMTPSecure = 'tls'; 'ssl';         // Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` encouraged
	    $mail->Port       = 587;                                    // TCP port to connect to, use 465 for `PHPMailer::ENCRYPTION_SMTPS` above

	    //Recipients
	    $mail->setFrom('hello@mindempathy.net', $name);
	    $mail->addAddress('hello@mindempathy.net', 'ME net');     // Add a recipient
	    $mail->addReplyTo($email);

	    if (!empty($files)) {
	    	foreach ($files as $key => $file) {
		    	$mail->addAttachment(
		    		$file['tmp_name'],
		    		$file['name']
		    	);
	    	}
	    }
	    // Content
	    $mail->isHTML(true);                                  // Set email format to HTML
	    $mail->Subject = 'New message at mindempathy.net from '.$name;
	    $mail->Body    = $html;
	    $mail->AltBody = strip_tags($html);

	    $mail->send();
	    responseHandler(true, 'Message sent successfully!');
	} catch (Exception $e) {
		responseHandler(false, 'Message could not be sent. Mailer Error: '.$mail->ErrorInfo);
	}
}