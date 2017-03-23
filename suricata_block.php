<?php
require('routeros_api.class.php');
header('Content-Type: text/plain');

$user_name = "snorby"; /* Database username */
$password = "snorby";  /* Database password */
$database = "snorby";
$server = "localhost";

$API = new routeros_api();

    /* Wait for a connection to the database */
    $i = 0;
    while ( $i < 100 ) {
      $db = new mysqli($server, $user_name, $password, $database);
      if ($db->connect_errno > 0) {
        print('Unable to connect to database [' . $db->connect_error . ']');
        sleep(10);
        $i = $i + 10;
      }
      else {
        $i = 100;
      }
    }

    while ( 1 == 1 ) {
      $SQL = "SELECT * FROM block_queue WHERE que_processed = 0;";
      if(!$result = $db->query($SQL)) {
          die('There was an error running the query [' . $db->error . ']');
      }
      while($row = $result->fetch_assoc()) {
        if (strpos($row['que_ip_adr'], '10.0.') !== true) {
          /* Does not match local address... */
          /* See if the address is already in the firewall list, if so delete it so we can readd it with a new timeout */
          try {
              $API->connect('10.0.0.1', 'suricata', 'suricata');
          } catch (Exception $e) {
              die('Unable to connect to RouterOS. Error:' . $e);
          }
          $ARRAY = $API->comm("/ip/firewall/address-list/print", array(
            ".proplist"=> ".id",
            "?address" => $row['que_ip_adr'],));
          foreach ($ARRAY as $a) {
            foreach ($a as $name => $value) {
              $API->write("/ip/firewall/address-list/remove",false);
              $API->write("=.id=$value",true);
              $API->read();
            }
          }
          /* Now add the address into the Blocked address-list group */
          $API->comm("/ip/firewall/address-list/add", array(
            "list" => "Blocked",
            "address" => $row['que_ip_adr'],
            "timeout" => $row['que_timeout'],
            "comment" => "From suricata, " . $row['que_sig_name'] . " => " . $row['que_sig_gid'] . ":" . $row['que_sig_sid'] .
               " => event timestamp: " . $row['que_event_timestamp'],));
          $API->disconnect();
        } else {
          /* Send email indicating bad block attempt*/
          $to      = 'noreply@noreply.com';
          $subject = 'Suricata on snort-host: attempted block on local address';
          $message = 'A record in the block_queue indicated a block on a local IP Address (' . $row['que_ip_adr'] . ")\r\n";
          $message = $message . "\r\n";
          $message = $message . "The signature ID is " . $row['que_sig_id'] . " named: " . $row['que_sig_name'] . "\r\n";
          $message = $message . "    with a que_id of " . $row['que_id'] . "\r\n\r\n";
          $message = $message . "Check the src_or_dst field in events_to_block for the signature to make sure it is correct (src/dst).\r\n\r\n";
          $message = $message . "The record was not processed but marked as completed.\r\n";
          $headers = 'From: noreply@noreply.com' . "\r\n" .
            'Reply-To: noreply@noreply' . "\r\n" .
            'X-Mailer: PHP/' . phpversion();
          mail($to, $subject, $message, $headers);
        }
      $SQL2 = "UPDATE block_queue set que_processed = 1 WHERE que_id = " . $row['que_id'] . ";";
      if (!$result2 = $db->query($SQL2)) {
        die('There was an error running the query [' . $db->error . ']');
        }
     // mysqli_free_result($result2);
      }
    mysqli_free_result($result);
    sleep(5); /* Sleep 5 seconds then do again */
    mysqli_ping($db);
    }
  $db->close();
?>
