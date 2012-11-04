<?php

# #######################################################
#
# Name: SSPB (Super Simple PHP Blog)
# 
# Version: 0.1
#
# Date: 04/16/2012
#
# Author: Adam Compton (adam.compton [at] gmail.com)
#
# Description:  SSPB is a small "blog" class which allow
#	a developer to include a "blog" into their
#	custom/pre exisiting website.  All the developer
#	needs to do is:
#		1) use PHP & MySQL
#		2) use the mysqli php database connection
#			functions
#		3) set up the blog database tables
#		4) include the appropiate class function
#			calls whereever they desire to
#			have the blog content displayed
#
# Change Log: 0.1 - 04/16/2012 - Initial code development
#
# #######################################################

# #######################################################
#
# BLOG DATABASE STRUCTURE:
#
# CREATE TABLE IF NOT EXISTS `blog` (
#   `bid` int(11) NOT NULL AUTO_INCREMENT,
#   `title` varchar(255) NOT NULL,
#   `author` varchar(255) NOT NULL,
#   `date` datetime NOT NULL,
#   `body` text NOT NULL,
#   UNIQUE KEY `bid` (`bid`)
# ) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;
#
# #######################################################

class blog {
	private $SUMMARY_LENGTH = 100;
	private $MYSQLI = NULL;
	private $SHARED_DB = FALSE;

	public function __construct() {
	}

	public function setDB($db) {
		if (!$this->SHARED_DB && $this->MYSQLI != NULL) $this->MYSQLI.close();
		$this->MYSQLI = $db;
		$this->SHARED_DB = TRUE;
	}
	
	public function setDBConnection($user, $password, $host, $database) {
		if (!$this->SHARED_DB && $this->MYSQLI != NULL) $this->MYSQLI.close();
		$this->MYSQLI = new mysqli($host, $user, $password, $database);
		if ($this->MYSQLI->connect_errno)
			echo "Failed to connect to MySQL: (" . $this->MYSQLI->connect_errno . ") " . $this->MYSQLI->connect_error;
		$this->SHARED_DB = FALSE;
	}
			
	public function doesPostExist($i) {
		if ($this->MYSQLI == NULL) return -1;
		
		$query = "SELECT `title` from `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();
		
		$value = FALSE;
		
		$result = $stmt->get_result();
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$value = TRUE;
			$result->close();
		}
		$stmt->close();
		
		return $value;
	}

	public function getPostTitle($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "SELECT `title` from `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();
		
		$value = null;
		
		$result = $stmt->get_result();
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$value = stripslashes($row[0]);
			$result->close();
		}
		$stmt->close();
		
		return $value;
	}

	public function getPostAuthor($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "SELECT `author` from `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();
		
		$value = null;
		
		$result = $stmt->get_result();
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$value = stripslashes($row[0]);
			$result->close();
		}
		$stmt->close();
		
		return $value;
	}

	public function getPostDate($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "SELECT `date` from `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();
		
		$value = null;
		
		$result = $stmt->get_result();
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$value = stripslashes($row[0]);
			$result->close();
		}
		$stmt->close();
		
		return $value;
	}

	public function getPostBodySummary($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$body = $this->getPostBody($i);
		$bodyLength = strlen($body);
		
		if ($bodyLength <= $this->SUMMARY_LENGTH) return $body;
		
		$body = substr($body, 0, $this->SUMMARY_LENGTH).' ... ';
		
		return $body;
	}
	
	public function getPostBody($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "SELECT `body` from `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();

		$value = null;
		
		$result = $stmt->get_result();
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$value = $row[0];
			$result->close();
		}
		$stmt->close();
		
		return $value;
	}
	
	public function displayPostSummary($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		echo '<p><font size=+1><strong>' . $this->getPostTitle($i) . '</strong></font></p>'; 
		echo '<br />';
		echo '<p> -- ' . $this->getPostAuthor($i) . ' (' . $this->getPostDate($i) . ' )</p>';
		echo '<br>';
		echo '<p>' . $this->getPostBodySummary($i) . '</p>';
	}

	public function displayPost($i) {
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		echo '<p><font size=+1><strong>' . $this->getPostTitle($i) . '</strong></font></p>'; 
		echo '<br />';
		echo '<p> -- ' . $this->getPostAuthor($i) . ' (' . $this->getPostDate($i) . ' )</p>';
		echo '<br>';
		echo '<p>' . $this->getPostBody($i) . '</p>';
	}

	public function getPostCount() {
		if ($this->MYSQLI == NULL) return -1;

		$count = 0;

		$query = "SELECT MAX(`bid`) FROM `blog`";
		$result = $this->MYSQLI->query($query);
		if ($result) {
			$row = $result->fetch_row();
			if ($row)
				$count = $row[0];
			$result->close();
		}
		
		return $count;
	}
	
	public function displayPostSummaryList($first,$last) {
		if ($this->MYSQLI == NULL) return -1;
		
		if ($first > $last) return;
		
		$count = $this->getPostCount();
		
		if ($first > $count) return;
		if ($last > $count) $last = $count;
		
		echo '<hr>';
		for ($i = $start; $i <= $last; $i++) {
			if (soesPostExist($i)) {
				$this->displayPostSummary($i);
				echo '<hr>';
			}
		}			
	}
	
	public function createPost($title, $author, $body){
		if ($this->MYSQLI == NULL) return -1;
		
		$query = "INSERT INTO `blog` (`title`, `author`, `date`, `body`) VALUES (?, ?, NOW(), ?)";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('sss',$title,$author,$body);
		$stmt->execute();
		$stmt->close();

		return $this->MYSQLI->insert_id;
	}

	public function updatePost($i, $title, $author, $body){
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "UPDATE `blog` SET `title` = ?, `author` = ?, `body` = ? WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('sssi',$title,$author,$body,$i);
		$stmt->execute();
		$stmt->close();
	}
	
	public function deletePost($i){
		if ($this->MYSQLI == NULL) return -1;
		if (!$this->doesPostExist($i)) return;
		
		$query = "DELETE FROM `blog` WHERE `bid` = ?";
		$stmt = $this->MYSQLI->prepare($query);
		$stmt->bind_param('i',$i);
		$stmt->execute();
		$stmt->close();
	}
	
	public function displayPostList(){
		if ($this->MYSQLI == NULL) return -1;
		
		$count = $this->getPostCount();

		if ($count == 0) return;

		echo '<hr>';
		for ($i = 1; $i <= $count; $i++) {
			if ($this->doesPostExist($i)) {
				$this->displayPost($i);
				echo '<hr>';
			}
		}			
	}
}

?>
