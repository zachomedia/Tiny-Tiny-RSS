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
