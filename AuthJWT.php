<?php

/*
 * LimeSurvey JWT Authentication Plugin for Limesurvey 3.14+
 * Author: Adam Zammit <adam.zammit@acspri.org.au>
 * License: GNU General Public License v3.0
 *
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 */

class AuthJWT extends LimeSurvey\PluginManager\AuthPluginBase
{
    protected $storage = 'LimeSurvey\PluginManager\DbStorage';

    static protected $description = 'JWT authentication';
    static protected $name = 'AuthJWT';

    protected $JWTToken = null;
    
    protected $settings = array(
        'authjwt_method' => array(
            'type' => 'select',
            'label' => 'Method for JWT authentication',
            'options' => array('HS256'=>'HS256','ES256'=>'ES256','HS384'=>'HS384','HS512'=>'HS512','RS256'=>'RS256','RS384'=>'RS384','RS512'=>'RS512'),
            'default' => 'HS256',
        ),
        'authjwt_key' => array(
            'type' => 'string',
            'label' => 'Shared secret key (for ES256,HS256,HS384 or HS512 methods) or Public Key (for RS256,RS384,RS512 methods) for JWT authentication',
            'default' => '',
        ),
        'authjwt_users_name_attr' => array(
            'type' => 'string',
            'label' => 'Name of attribute containing the username (required and unique)',
            'default' => 'username',
        ),
        'authjwt_email_attr' => array(
            'type' => 'string',
            'label' => 'Name of attribute containing the email address (leave blank to auto generate)',
            'default' => '',
        ),
        'authjwt_full_name' => array(
            'type' => 'string',
            'label' => 'Name of attribute containing the display name (leave blank to auto generate based on users name)',
            'default' => '',
        ),
        'auto_login' => array(
            'type' => 'checkbox',
            'label' => 'Auto login when a JWT token is provided',
            'default' => true,
        ),
        'auto_create_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto create users',
            'default' => true,
        ),
        'auto_update_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
        'storage_base' => array(
            'type' => 'string',
            'label' => 'Storage base',
            'default' => 'DbStorage',
        ),
        'logout_redirect' => array(
            'type' => 'string',
            'label' => 'Logout Redirect URL',
            'default' => '/admin',
        ),
        'auto_update_users' => array (
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
        'allowInitialUser' => array(
            'type' => 'checkbox',
            'label' => 'Allow initial user to login via JWT',
        ),
        'auto_create_labelsets' => array (
            'type' => 'string',
            'label' => '- Permissions: Label Sets',
            'default' => '',
        ),
        'auto_create_participant_panel' => array (
            'type' => 'string',
            'label' => '- Permissions: Participant panel',
            'default' => '',
        ),
        'auto_create_settings_plugins' => array (
            'type' => 'string',
            'label' => '- Permissions: Settings & Plugins',
            'default' => '',
        ),
        'auto_create_surveys' => array (
            'type' => 'string',
            'label' => '- Permissions: Surveys',
            'default' => 'create_p,read_p,update_p,delete_p,export_p',
        ),
        'auto_create_templates' => array (
            'type' => 'string',
            'label' => '- Permissions: Templates',
            'default' => 'create_p,read_p,update_p,delete_p,import_p,export_p',
        ),
        'auto_create_user_groups' => array (
            'type' => 'string',
            'label' => '- Permissions: User groups',
            'default' => 'create_p,read_p,update_p,delete_p',
        ),
    );

    public function init() {
        $this->storage = $this->get('storage_base', null, null, $this->settings['storage_base']['default']);

        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeHasPermission');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');
        $this->subscribe('afterFailedLoginAttempt');
        $this->subscribe('newLoginForm');
        $this->subscribe('afterLoginFormSubmit'); //need this to avoid password being reset
    }


    public function newLoginForm()                                              
    {                                                                           
        $sPassword = $this->getBearerToken();
        $this->getEvent()->getContent($this)
                         ->addContent(CHtml::tag('span', array(), "<label for='password'>".gT("JWT Token")."</label>".CHtml::passwordField('password', $sPassword, array('size'=>256, 'class'=>"form-control"))));

        //if token is set, also auto login if requested
        $auto_login  = $this->get('auto_login', null, null, true);
        if ($auto_login && !empty($sPassword)) {
            App()->getClientScript()->registerScript("autoLoginScript",'$( document ).ready(function() { $( "button" ).trigger( "click" );});');
		}
    }                                                                           
           

    /**
     * Add AuthJWT Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_jwt' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use JWT authentication"),
                'description' => gT("Use JWT authentication"),
                'img' => 'usergroup'
            ),
        ));
    }

    /**
     * Validation of AuthPermission (for super-admin only)
     * @return void
     */
    public function beforeHasPermission()
    {
        $oEvent = $this->getEvent();
        if ($oEvent->get('sEntityName') != 'global' || $oEvent->get('sPermission') != 'auth_jwt' || $oEvent->get('sCRUD') != 'read') {
            return;
        }
        $iUserId = Permission::getUserId($oEvent->get('iUserID'));
        if ($iUserId == 1) {
            $oEvent->set('bPermission', (bool) $this->get('allowInitialUser'));
        }
    }

    public function beforeLogin() {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $jwt = $this->getBearerToken();
        if ($jwt !== null) {
            $showingError = $this->getFlash('showing_error', false);
            $this->log(__METHOD__.' - showingError: '.($showingError ? 'true' : 'false'), \CLogger::LEVEL_TRACE);
            if (! $showingError && ! FailedLoginAttempt::model()->isLockedOut() ) {
            
                $this->log(__METHOD__.' - JWT Token: '.$jwt, \CLogger::LEVEL_TRACE);
                $this->setJWTToken($jwt);
                $this->getEvent()->set('default', get_class($this)); //make this the default if data is passed
            }
        }

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    private function setJWTToken($jwt) 
    {
        $this->JWTToken = $jwt;
    }

    private function getJWTToken() 
    {
        return $this->JWTToken;
    }

    private function getFlash($key, $defaultValue= null)
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $fqKey = 'AuthJWT.'.$key;
        $result = Yii::app()->session->remove($fqKey);
        if ($result === null) {
            $result = $defaultValue;
        }

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

        return $result;
    }

    private function setFlash($key, $value, $defaultValue = null)
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $fqKey = 'AuthJWT.'.$key;

        if ($value === $defaultValue) {
            Yii::app()->session->remove($fqKey);
        } else {
            Yii::app()->session->add($fqKey, $value);
        }

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

    }

    public function afterFailedLoginAttempt()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $this->setFlash('showing_error', true);

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    public function afterLogout()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $redirect = $this->get('logout_redirect', null, null, $this->settings['logout_redirect']['default']);
        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

        Yii::app()->controller->redirect($redirect);
        Yii::app()->end();

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    public function newUserSession()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        // Do nothing if this user is not AuthJWT type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != get_class($this)) {
            $this->log(__METHOD__.' - Authentication not managed by this plugin', \CLogger::LEVEL_TRACE);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        /* unsubscribe from beforeHasPermission, else current event will be modified during check permissions */
        $this->unsubscribe('beforeHasPermission');

		//see if we have a valid JWT header (as password field)
		$jwt = $this->getPassword();
        if ($jwt !== null) {
            //see if it decodes correctly
            require_once(dirname(__FILE__).'/php-jwt/src/JWT.php');
            require_once(dirname(__FILE__).'/php-jwt/src/BeforeValidException.php');
            require_once(dirname(__FILE__).'/php-jwt/src/SignatureInvalidException.php');
            require_once(dirname(__FILE__).'/php-jwt/src/ExpiredException.php');
            try {
                $payload = \Firebase\JWT\JWT::decode($jwt, $this->get('authjwt_key', null, null, true), array($this->get('authjwt_method', null, null, true)));
            } catch (Exception $e) {
                //failed login
                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Failed to login. Please go back and try again (your token is not valid, it may have expired)'));
            	$this->log(__METHOD__.' - ERROR: Failed to decode JWT payload', \CLogger::LEVEL_ERROR);
	            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
				return;				
            }
        } else {
            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Limesurvey did not receive JWT token in header'));
            $this->log(__METHOD__.' - ERROR: Limesurvey did not receive JWT token in header', \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
			return;
		}

        $jwtConfigurationError = isset(Yii::app()->session['AuthJWT_configuration_error']);
        if ($jwtConfigurationError){
            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Limesurvey is not configured properly to use the SSO'));
            $this->log(__METHOD__.' - ERROR: Limesurvey is not configured properly to use the SSO', \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        $sUser = $this->getUserNameJWT($payload);
        $name = $this->getUserCommonName($payload);
        $mail = $this->getUserMail($payload);

        if (empty($sUser)) {
            $attributeName = $this->getUserNameJWTAttributeName();

            Yii::app()->session['AuthJWT_configuration_error'] = true;

            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Required JWT attribute missing'));

            $this->log(__METHOD__." - ERROR: Missing required attribute '$attributeName' in JWT response.", \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        // Get LS user
        $oUser = $this->api->getUserByName($sUser);

        if (is_null($oUser)) {
            $auto_create_users = $this->get('auto_create_users', null, null, true);
            if ($auto_create_users) {
                // Create new user
                $oUser = new User;
                $oUser->users_name = $sUser;
                $oUser->setPassword(createPassword());
                $oUser->full_name = $name;
                $oUser->parent_id = 1;
                $oUser->email = $mail;

                if ($oUser->save()) {
                    $this->assignUserPermissions($oUser->uid);

                    $oUser = $this->api->getUserByName($sUser);

                    $this->setUsername($sUser);


					$this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
                    $this->setAuthSuccess($oUser);
                    $this->log(__METHOD__.' - User created: '.$oUser->uid, \CLogger::LEVEL_INFO);
                } else {
                    $this->log(__METHOD__.' - ERROR: Could not add the user: '.$oUser->uid, \CLogger::LEVEL_ERROR);

                    $this->setAuthFailure(self::ERROR_NOT_ADDED);
                }
            } else {
                $this->log(__METHOD__.' - ERROR: User creation not allowed: '.$oUser->uid, \CLogger::LEVEL_ERROR);
                $this->setAuthFailure(self::ERROR_NOT_ADDED, gT("We are sorry but you do not have an account."));
            }
        } else {

            // If user cannot login via JWT: setAuthFailure
            if (($oUser->uid == 1 && !$this->get('allowInitialUser'))
                || !Permission::model()->hasGlobalPermission('auth_jwt', 'read', $oUser->uid))
            {
                $this->log(__METHOD__.' - ERROR: authentication method is not allowed for this user: '.$oUser->uid, \CLogger::LEVEL_ERROR);
                $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('JWT authentication method is not allowed for this user'));
                return;
            }

            // *** Update user ***
            $auto_update_users = $this->get('auto_update_users', null, null, $this->settings['auto_update_users']['default']);

            if ($auto_update_users) {
                $changes = array (
                    'full_name' => $name,
                    'email' => $mail,
                );

                User::model()->updateByPk($oUser->uid, $changes);
                $oUser = $this->api->getUserByName($sUser);
            }

            $this->setUsername($sUser);
			$this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
            $this->setAuthSuccess($oUser);
            $result = $this->getEvent()->get('result');
            $this->log(__METHOD__.' - User updated: '.$oUser->uid, \CLogger::LEVEL_TRACE);
        }
        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    private function assignUserPermissions(string $uid)
    {
        Permission::model()->setGlobalPermission($uid, 'auth_jwt');

        Permission::model()->insertSomeRecords(array ('uid' => $uid, 'permission' => getGlobalSetting("defaulttheme"), 'entity_id' => 0, 'entity' => 'template', 'read_p' => 1));

        // Set permissions: Label Sets
        $auto_create_labelsets = $this->get('auto_create_labelsets', null, null, $this->settings['auto_create_labelsets']['default']);
        if ($auto_create_labelsets) {
            Permission::model()->setGlobalPermission($uid, 'labelsets', array('create_p', 'read_p', 'update_p', 'delete_p', 'import_p', 'export_p'));
        }

        // Set permissions: Participant Panel
        $auto_create_participant_panel = $this->get('auto_create_participant_panel', null, null, $this->settings['auto_create_participant_panel']['default']);
        if ($auto_create_participant_panel) {
            Permission::model()->setGlobalPermission($uid, 'participantpanel', array('create_p', 'read_p', 'update_p', 'delete_p', 'import_p', 'export_p'));
        }

        // Set permissions: Settings & Plugins
        $auto_create_settings_plugins = $this->get('auto_create_settings_plugins', null, null, $this->settings['auto_create_settings_plugins']['default']);
        if ($auto_create_settings_plugins) {
            Permission::model()->setGlobalPermission($uid, 'settings', array('read_p', 'update_p', 'import_p'));
        }

        // Set permissions: surveys
        $auto_create_surveys = $this->get('auto_create_surveys', null, null, $this->settings['auto_create_surveys']['default']);
        if ($auto_create_surveys) {
            Permission::model()->setGlobalPermission($uid, 'surveys', explode(',', $auto_create_surveys));
        }

        // Set permissions: Templates
        $auto_create_templates = $this->get('auto_create_templates', null, null, $this->settings['auto_create_templates']['default']);
        if ($auto_create_templates)	{
            Permission::model()->setGlobalPermission($uid, 'templates', explode(',', $auto_create_templates));
        }

        // Set permissions: User Groups
        $auto_create_user_groups = $this->get('auto_create_user_groups', null, null, $this->settings['auto_create_user_groups']['default']);
        if ($auto_create_user_groups) {
            Permission::model()->setGlobalPermission($uid, 'usergroups', explode(',', $auto_create_user_groups));
        }
    }

    public function getUserNameJWT($jwt)
    {
        return $this->getJWTAttribute($jwt,$this->getUserNameJWTAttributeName());
    }

    public function getUserNameJWTAttributeName()
    {
        return $this->get('authjwt_users_name_attr', null, null, $this->settings['authjwt_users_name_attr']['default']);
    }

    public function getJWTAttribute($jwt,string $attribute_name)
    {
        $attributeValue = '';

        if (!empty($jwt)) {
            if (isset($jwt->$attribute_name) && !empty($jwt->$attribute_name))	{
                $attributeValue = $jwt->$attribute_name;
            }
        }
        return $attributeValue;
    }

    public function getUserCommonName($jwt)
    {
        $name = $this->getJWTAttribute($jwt,$this->getUserCommonNameJWTAttributeName());
        if (empty($name) || $name == "") {
            $name = $this->getUserNameJWT($jwt);
        }
        return $name;
    }

    private function getUserCommonNameJWTAttributeName()
    {
        return $this->get('authjwt_full_name', null, null, $this->settings['authjwt_full_name']['default']);
    }

    public function getUserMail($jwt)
    {
        $email = $this->getJWTAttribute($jwt,$this->getUserMailJWTAttributeName());
        if (empty($email) || $email == "") {
            $email = "lime@lime.com";
        }
        return $email;
    }

    private function getUserMailJWTAttributeName()
    {
        return $this->get('authjwt_email_attr', null, null, $this->settings['authjwt_email_attr']['default']);
    }

    /**
     * Get header Authorization
     * Source: https://stackoverflow.com/questions/40582161/how-to-properly-use-bearer-tokens
     * */
    private function getAuthorizationHeader(){
            $headers = null;
            if (isset($_SERVER['Authorization'])) {
                $headers = trim($_SERVER["Authorization"]);
            }
            else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
                $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
            } elseif (function_exists('apache_request_headers')) {
                $requestHeaders = apache_request_headers();
                // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
                $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
                //print_r($requestHeaders);
                if (isset($requestHeaders['Authorization'])) {
                    $headers = trim($requestHeaders['Authorization']);
                }
            }
            return $headers;
        }

    /**
     * get access token from header
     * Source: https://stackoverflow.com/questions/40582161/how-to-properly-use-bearer-tokens
     * */
    private function getBearerToken() {
		$request = $this->api->getRequest();
		if (!is_null($request->getParam('jwt'))) {
			return $request->getParam('jwt');
		}
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
}
