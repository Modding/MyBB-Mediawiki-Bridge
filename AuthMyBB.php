<?php
require_once "includes/AuthPlugin.php";

class AuthMyBB extends AuthPlugin {
	/**
	 * @var string The path to your copy of MyBB (with a trailing slash)
	 */
	var $forum_path = "RELATIVE PATH TO FORUMROOT";

	/**
	 * @var array An array of user group IDs for banned user groups (defaults to the MyBB banned group)
	 */
	var $banned_usergroups = array(7);
	
	/**
	 * @var array An array of group IDs which should have SysOp/Administrative access to the wiki (defaults to Super Moderators and Administrators)
	 */
	var $admin_usergroups = array(4,3);
	var $searchpattern = "/[^a-zA-Z0-9 ]+/";

	var $db;
	var $table_prefix;
	var $config;

	function AuthMyBB()
	{
		if(!file_exists($this->forum_path."inc/config.php"))
		{
			die("Could not find MyBB configuration file. Please check the path is correct.");
		}

		require_once $this->forum_path."inc/config.php";
		$this->table_prefix = $config['database']['table_prefix'];
		$this->config = $config;
	}

	/* Interface documentation copied in from AuthPlugin */
	/**
	 * Check whether there exists a user account with the given name.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param string $username
	 * @return bool
	 * @access public
	 */

	function openDB()
	{
		$this->db = mysql_connect($this->config['database']['hostname'], $this->config['database']['username'], $this->config['database']['password']) or die("Unable to connect to MyBB database.");
		mysql_select_db($this->config['database']['database']) or die("Unable to select MyBB database");
		
	}

	function userExists($username)
	{
		if(!is_object($this->db)) { $this->openDB(); }
		$query = mysql_query("SELECT username FROM {$this->table_prefix}users WHERE username='".$this->escape_string($username)."'", $this->db);
		$user = mysql_fetch_assoc($query);
		if($user['username'])
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Check if a username+password pair is a valid login.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param string $username
	 * @param string $password
	 * @return bool
	 * @access public
	 */

	function authenticate($username, $password)
	{
		if(!is_object($this->db)) { $this->openDB(); }
		$query = mysql_query("SELECT username,password,salt,usergroup FROM {$this->table_prefix}users WHERE username='".$this->escape_string($username)."'", $this->db);
		$user = mysql_fetch_array($query);
		$saltedpw = md5(md5($user['salt']).md5($password));
		if($user['username'] && $user['password'] == $saltedpw)
		{
			if(in_array($user['usergroup'], $this->banned_usergroups))
			{
				return false;
			}
			return true;
		}
		else
		{
			return false;
		}
	}
	
	/**
	 * Modify options in the login template.
	 *
	 * @param UserLoginTemplate $template
	 * @access public
	 */
	function modifyUITemplate(&$template, &$type)
	{
		$template->set('usedomain', false);
		$template->set('useemail', false);
		$template->set('create', false);
	}

	/**
	 * Set the domain this plugin is supposed to use when authenticating.
	 *
	 * @param string $domain
	 * @access public
	 */
	function setDomain( $domain ) {
		$this->domain = $domain;
	}

	/**
	 * Check to see if the specific domain is a valid domain.
	 *
	 * @param string $domain
	 * @return bool
	 * @access public
	 */
	function validDomain( $domain ) {
		# Override this!
		return true;
	}

	/**
	 * When a user logs in, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param User $user
	 * @access public
	 */
	function updateUser( &$user ) {
		if(!is_resource($this->db)) { $this->openDB(); }
		$query = mysql_query("SELECT username,email,usergroup,additionalgroups FROM {$this->table_prefix}users WHERE username='".$this->escape_string($user->mName)."'", $this->db);
		$res = mysql_fetch_array($query);

		if($res)
		{
			if(in_array($res['usergroup'], $this->admin_usergroups))
			{
				$is_admin = true;
			}
			$memberships = explode(",", $res['additionalgroups']);
			
			for($i=0;$i<count($memberships);$i++)
			{
				if(in_array($memberships[$x], $this->admin_usergroups))
				{
					$is_admin = true;
				}
			}
			
			if($is_admin == true)
			{
				// If a user is not a sysop, make them a sysop
				if (!in_array("sysop", $user->getEffectiveGroups())) {
					$user->addGroup('sysop');
				}				
			}
			else
			{
				if (in_array("sysop", $user->getEffectiveGroups())) {
					$user->removeGroup('sysop');
					return TRUE;
				}				
			}
			
			$user->setEmail($res['email']);
			$user->setRealName($res['username']);
			return TRUE;
		}
		return false;
	}


	/**
	 * Return true if the wiki should create a new local account automatically
	 * when asked to login a user who doesn't exist locally but does in the
	 * external auth database.
	 *
	 * If you don't automatically create accounts, you must still create
	 * accounts in some way. It's not possible to authenticate without
	 * a local account.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @access public
	 */
	function autoCreate() {
		return true;
	}
	
	/**
	 * Set the given password in the authentication database.
	 * Return true if successful.
	 *
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function setPassword($user, $password ) {
		return true;
	}

	/**
	 * Update user information in the external authentication database.
	 * Return true if successful.
	 *
	 * @param User $user
	 * @return bool
	 * @access public
	 */
	function updateExternalDB( $user ) {
		return false;
	}

	/**
	 * Check to see if external accounts can be created.
	 * Return true if external accounts can be created.
	 * @return bool
	 * @access public
	 */
	function canCreateAccounts() {
		return false;
	}

	/**
	 * Add a user to the external authentication database.
	 * Return true if successful.
	 *
	 * @param User $user
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function addUser($user, $password, $email = '', $realname = '') {
		return false;
	}


	/**
	 * Return true to prevent logins that don't authenticate here from being
	 * checked against the local database's password fields.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @access public
	 */
	function strict() {
		return true;
	}
	
	/**
	 * When creating a user account, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param User $user
	 * @access public
	 */
	function initUser(&$user, $autocreate = false) {
		$user->mEmailAuthenticated = wfTimestampNow();
		$this->updateUser( $user );
	}

	/**
	 * If you want to munge the case of an account name before the final
	 * check, now is your chance.
	 */
	function getCanonicalName ( $username ) {
		// connecting to MediaWiki database for this check 		
		$dbr =& wfGetDB( DB_SLAVE );
		
		$res = $dbr->selectRow('user',
				       array("user_name"),
				       "lower(user_name)=lower(".
				         $dbr->addQuotes($username).")",
				       "AuthMyBB::getCanonicalName" );
		
		if($res) {
			return $res->user_name;
		} else {
			return $username;
		}
	}

	function escape_string($string)
	{
		if(function_exists("mysql_real_escape_string"))
		{
			return mysql_real_escape_string($string, $this->db);
		}
		else
		{
			return addslashes($string);
		}
	}
}
?>