<?php
interface IAuthModule {
	function authenticate($login, $password);
	function logout();
}
?>
