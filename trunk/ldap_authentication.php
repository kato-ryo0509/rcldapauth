<?php

/**
 * LDAP Authentication
 *
 * LDAP authentication plugin based on Thomas Bruederli http_authentication 
 * plugin.
 * Authenticate on LDAP server using PEAR Auth module, and create 
 * user identity based on LDAP information.
 *
 * @version 1.0
 * @author SIMB Tecnologia - http://www.simb.com.br/
 * @author Vitor Espindola
 */
 
require_once 'PEAR.php';
require_once 'Auth.php';

class ldap_authentication extends rcube_plugin
{
  
	var $auth;
	var $config;
	
	function init()
	{
		$this->_configure();
		$this->add_hook('authenticate', array($this, 'authenticate'));
		$this->add_hook('create_user', array($this, 'create_user'));
	}

	function _configure() {
	
		$this->load_config('config.inc.php.dist');
		$this->load_config('config.inc.php');
		$rcmail = rcmail::get_instance();
	
		$this->config = $rcmail->config->get('ldapauth');
		$this->config['postUsername'] = '_user';
		$this->config['postPassword'] = '_pass';
		$this->config['attributes'] = array(
			$this->config['attr_name'],
			$this->config['attr_mail'],
			$this->config['attr_user']
		);
		
		$this->auth = new Auth("LDAP", $this->config, false, false);
	}

	function authenticate($args)
	{
		$this->auth->start();
		
		if ($this->auth->checkAuth()) {
			$data = $this->auth->getAuthData();
			$args['user'] = $data[$this->config['attr_user']];
		}
		return $args;
	}


	function create_user($args)
	{
		$data = $this->auth->getAuthData();	
		$args['user_email'] = $data[$this->config['attr_mail']];
		$args['user_name'] = $data[$this->config['attr_name']];
		return $args;
	}
}

