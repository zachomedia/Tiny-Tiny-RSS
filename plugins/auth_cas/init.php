<?php

require 'CAS.php';

class Auth_CAS extends Plugin implements IAuthModule {

    private $host;
    private $base;
    private $initialized;

    function __construct() {
        $this->initialized = false;
    }

    function about() {
        return array(1.0,
            "Authenticates against a Central Authentication System",
            "Zachary Seguin",
            true);
    }

    function init_phpcas() {
        if ($this->initialized) return;

        phpCAS::client(CAS_VERSION_2_0, AUTH_CAS_SERVER, AUTH_CAS_PORT, AUTH_CAS_CONTEXT);
        phpCAS::setNoCasServerValidation();
        $this->initialized = true;
    }

    function init($host) {
        $this->host = $host;
        $this->base = new Auth_Base();

        $host->add_hook($host::HOOK_AUTH_USER, $this);
    }

    function authenticate($login, $password) {
        if (!$this->initialized) $this->init_phpcas();
        if (!empty($login) && !empty($password) && defined('AUTH_CAS_USE_LDAP_FOR_API') && AUTH_CAS_USE_LDAP_FOR_API) {
           $ldap = ldap_connect(AUTH_CAS_LDAP_HOST);

           if (!$ldap) return false;

           ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
           ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

           $search_result = ldap_search($ldap, AUTH_CAS_LDAP_SEARCH_BASE, str_replace("$1", $login, AUTH_CAS_LDAP_SEARCH_PARAM), array('dn'));
           if ($search_result === FALSE) return false;

           $user_results = ldap_get_entries($ldap, $search_result);
           if ($user_results['count'] === 0) return false;

           $bind_result = ldap_bind($ldap, $user_results[0]['dn'], $password);
           if ($bind_result) return $this->base->auto_create_user($login, $password);

           return false;
        }// end of if

        phpCAS::handleLogoutRequests();
        phpCAS::forceAuthentication();

        return $this->base->auto_create_user(phpCAS::getUser(), $password);
    }

    function logout() {
        if (!$this->initialized) $this->init_phpcas();
        phpCAS::logout();
    }

    function api_version() {
        return 2;
    }

}

?>
