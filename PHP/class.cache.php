<?php

# #######################################################
#
# Name: PC (PHP Cache)
# 
# Version: 0.1
#
# Date: 04/16/2012
#
# Author: Adam Compton (adam.compton [at] gmail.com)
#
# Description:  PC is used to perform caching for web
#	content
#
# Change Log: 0.1 - 04/16/2012 - Initial code development
#
# #######################################################

# #######################################################
#
# Sample Useage:
# 
# $cache = new cache();
# if ($cache->getCache("test") {
#	 // auto matically displays cached data
# } else {
# 	ob_start();
# 	// do stuff
# 	$cache->setCache("test",ob_get_contents());
# 	ob_end_flush();
# }
#
# #######################################################

class cache {
	# cachefile directory
	private $CACHE_DIR = "../cache/";
	
	public function getCache($name, $age = 300) {
		#set cachefile name and path
		$cachefile = $this->CACHE_DIR . $name;
		
		# check if file exists and that it is not too old
		if (file_exists($cachefile) && ((time() - $age) < filemtime($cachefile))) {  
			# include the contents of the cache file
			include($cachefile);
			
			# return that a valid cache file was found
			return TRUE;
        }
		
		# return that a valid cache file was NOT found
		return FALSE;
	}
	
	public function setCache($name, $text) {
		# set cachefile name and path
		$cachefile = $this->CACHE_DIR . $name;
		
		# open cache file for writing
		$fp = fopen($cachefile, 'w+');
		
		# save contents of output buffer to the file
		fwrite($fp, $text);
		
		# close the file
		fclose($fp);
	}

	public function deleteCache($name) {
		#set cachefile name and path
		$cachefile = $this->CACHE_DIR . $name;
		
		# check if file exists
		if (file_exists($cachefile)) {  
			unlink($cachefile);
		}
	}
}
?>
