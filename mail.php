<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'config.php';
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

$files = [];
if (!empty($_FILES['file'])) {
	$files = restructureArray($_FILES['file']);
}

list($name, $email, $phone, $message) = array_values($_POST);

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

try {
	$mail->SMTPOptions = array(
		'ssl' => array(
			'verify_peer' => false,
			'verify_peer_name' => false,
			'allow_self_signed' => true
		)
	);
	//Server settings
    $mail->isSMTP();                                            // Send using SMTP
    $mail->Host       = CONFIG['email']['host'];                    // Set the SMTP server to send through
    $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
    $mail->Username   = CONFIG['email']['username'];                     // SMTP username
    $mail->Password   = CONFIG['email']['password'];                               // SMTP password
    $mail->SMTPSecure = CONFIG['email']['SMTPSecure']; 'ssl';         // Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` encouraged
    $mail->Port       = CONFIG['email']['port'];                                    // TCP port to connect to, use 465 for `PHPMailer::ENCRYPTION_SMTPS` above

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
	responseHandler(false, 'Message could not be sent. Mailer Error: ', $mail->ErrorInfo);
}