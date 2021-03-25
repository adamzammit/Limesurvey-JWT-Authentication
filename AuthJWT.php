<?php

/*
 * LimeSurvey Auhtnetication Plugin for Limesurvey 3.14+
 * Auhtor: Frank Niesten
 * License: GNU General Public License v3.0
 *
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 */

class AuthSAML extends LimeSurvey\PluginManager\AuthPluginBase
{
    protected $storage = 'LimeSurvey\PluginManager\DbStorage';
    protected $ssp = null;

    static protected $description = 'Core: SAML authentication';
    static protected $name = 'SAML';

    protected $settings = array(
        'simplesamlphp_path' => array(
            'type' => 'string',
            'label' => 'Path to the SimpleSAMLphp folder',
            'default' => '/usr/share/simplesamlphp',
        ),
        'simplesamlphp_cookie_session_storage' => array(
            'type' => 'checkbox',
            'label' => 'Does simplesamlphp use cookie as a session storage ?',
            'default' => true,
        ),
        'saml_authsource' => array(
            'type' => 'string',
            'label' => 'SAML authentication source',
            'default' => 'default-sp',
        ),
        'saml_uid_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as username',
            'default' => 'uid',
        ),
        'saml_mail_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as email',
            'default' => 'mail',
        ),
        'saml_group_mapping' => array (
            'type' => 'string',
            'label' => 'SAML attributed used for groups',
            'default' => 'member',
        ),
        'user_access_group' => array (
            'type' => 'string',
            'label' => 'User\'s group required to login using SAML',
        ),
        'saml_name_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as name',
            'default' => 'cn',
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
        'force_saml_login' => array(
            'type' => 'checkbox',
            'label' => 'Force SAML login.',
            'default' => false,
        ),
        'authtype_base' => array(
            'type' => 'string',
            'label' => 'Authtype base to modify the login form. If null, then no modification is done.',
            'default' => 'Authdb',
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
            'label' => 'Allow initial user to login via SAML',
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
        'simplesamlphp_logo_path' => array(
            'type' => 'logo',
            'label' => 'Plugin logo',
            'path' => 'assets/SSO_LOGO.svg',
            'alt' => 'SAML Logo',
            'style' => 'width:128px',
        ),
    );

    public function init() {
        $this->storage = $this->get('storage_base', null, null, $this->settings['storage_base']['default']);

        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeHasPermission');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');

        if (!$this->get('force_saml_login', null, null, $this->settings['force_saml_login']['default'])) {
            $this->subscribe('newLoginForm');
        }

        $this->subscribe('beforeActivate');
        $this->subscribe('afterFailedLoginAttempt');
    }

    public function beforeActivate()
    {
        if ( $this->get_saml_instance() === null ) {
            $event = $this->getEvent();
            $event->set('success', false);
            $event->set('message', gT("SAML authentication failed: Simplesamlphp installation not available."));
        }
    }

    /**
     * Add AuthSAML Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(


            'auth_saml' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use SAML authentication"),
                'description' => gT("Use SAML authentication"),
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
        if ($oEvent->get('sEntityName') != 'global' || $oEvent->get('sPermission') != 'auth_saml' || $oEvent->get('sCRUD') != 'read') {
            return;
        }
        $iUserId = Permission::getUserId($oEvent->get('iUserID'));
        if ($iUserId == 1) {
            $oEvent->set('bPermission', (bool) $this->get('allowInitialUser'));
        }
    }

    public function beforeLogin() {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $ssp = $this->get_saml_instance();

        $sessionCleanupNeeded = $this->isSessionCleanupNeeded();

        $ssp = $this->get_saml_instance();

        if ($this->get('force_saml_login', null, null, $this->settings['force_saml_login']['default'])) {
            $ssp->requireAuth();
        }

        $isAuthenticated = $ssp->isAuthenticated();

        if ($isAuthenticated) {
            $sUser = $this->getUserNameSAML();
            // must be done as early as possible and before touching LS session
            $this->doSessionCleanup($sessionCleanupNeeded);

            $showingError = $this->getFlash('showing_error', false);
            $this->log(__METHOD__.' - showingError: '.($showingError ? 'true' : 'false'), \CLogger::LEVEL_TRACE);
            if (! $showingError && ! FailedLoginAttempt::model()->isLockedOut() ) {

                $this->log(__METHOD__.' - sUser: '.$sUser, \CLogger::LEVEL_TRACE);

                $this->setUsername($sUser);
                $this->setAuthPlugin();
            }
        } else {
            // Do not want to move outside because session cleanup will be called twice in some cases
            $this->doSessionCleanup($sessionCleanupNeeded);
        }

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    private function isSessionCleanupNeeded()
    {
        $sessionCleanupNeeded = session_status() === PHP_SESSION_ACTIVE;
        $sessionCleanupRequired = $this->get('simplesamlphp_cookie_session_storage', null, null, $this->settings['simplesamlphp_cookie_session_storage']['default']);
        return $sessionCleanupNeeded && $sessionCleanupRequired;
    }

    private function doSessionCleanup($doIt=false)
    {
        if ($doIt) {
            \SimpleSAML\Session::getSessionFromRequest()->cleanup();
        }
    }

    private function getFlash($key, $defaultValue= null)
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $fqKey = 'AuthSAML.'.$key;
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

        $fqKey = 'AuthSAML.'.$key;

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

        $ssp = $this->get_saml_instance();

        if ($ssp->isAuthenticated()) {
            $redirect = $this->get('logout_redirect', null, null, $this->settings['logout_redirect']['default']);
            $redirect = Yii::app()->getController()->createUrl($redirect);

            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

            Yii::app()->controller->redirect($ssp->getLogoutUrl($redirect));
            Yii::app()->end();
        }

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    public function newLoginForm()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        $authtype_base = $this->get('authtype_base', null, null, $this->settings['authtype_base']['default']);

        $ssp = $this->get_saml_instance();
        $loginUrl = $ssp->getLoginURL();

        $pluginsettings = $this->getPluginSettings(true);
        $imgUrl = $pluginsettings['simplesamlphp_logo_path']['path'];

        if ($authtype_base != null) {
            // This add the login button to the auth_base authentication method
            $this->getEvent()
                ->getContent($authtype_base)
                ->addContent('<center>Click on that button to initiate SAML Login<br>
                    <a href="' . $loginUrl . '" title="SAML Login">
                    <img src="' .$imgUrl . '" width="100px"></a></center><br>
                    ', LimeSurvey\PluginManager\PluginEventContent::PREPEND);
        }

        // This generates the "login form" for this plugin, basically a link to follow.
        $this->getEvent()
            ->getContent($this)
            ->addContent('<center>Click on that button to initiate SAML Login<br>
                <a href="' . $loginUrl . '" title="SAML Login">
                 <img src="' . $imgUrl . '" width="100px"></a></center><br>
                 ');

        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    public function newUserSession()
    {
        $this->log(__METHOD__.' - BEGIN', \CLogger::LEVEL_TRACE);

        // Do nothing if this user is not AuthSAML type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != get_class($this)) {
            $this->log(__METHOD__.' - Authentication not managed by this plugin', \CLogger::LEVEL_TRACE);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        /* unsubscribe from beforeHasPermission, else current event will be modified during check permissions */
        $this->unsubscribe('beforeHasPermission');

        $ssp = $this->get_saml_instance();
        $isAuthenticated = $ssp->isAuthenticated();

        if (! $isAuthenticated) {

            $this->doSessionCleanup($this->isSessionCleanupNeeded());

            $this->setAuthFailure(self::ERROR_USERNAME_INVALID);

            $this->log(__METHOD__.' - ERROR: User not authenticated, but was expected', \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        $samlConfigurationError = isset(Yii::app()->session['AuthSAML_configuration_error']);
        if ($samlConfigurationError){

            $this->doSessionCleanup($this->isSessionCleanupNeeded());

            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Limesurvey is not configured properly to use the SSO'));

            $this->log(__METHOD__.' - ERROR: Limesurvey is not configured properly to use the SSO', \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        $sUser = $this->getUserNameSAML();
        $name = $this->getUserCommonName();
        $mail = $this->getUserMail();
        $usergroup = $this->getUserGroup();

        $this->doSessionCleanup($this->isSessionCleanupNeeded());

        if (empty($sUser)) {
            $attributeName = $this->getUserNameSAMLAttributeName();

            Yii::app()->session['AuthSAML_configuration_error'] = true;

            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Required SAML attribute missing'));

            $this->log(__METHOD__." - ERROR: Missing required attribute '$attributeName' in SAML response.", \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        if (empty($name)) {
            $attributeName = $this->getUserCommonNameSAMLAttributeName();

            Yii::app()->session['AuthSAML_configuration_error'] = true;

            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Required SAML attribute missing'));

            $this->log(__METHOD__." - ERROR: Missing required attribute '$attributeName' in SAML response.", \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }

        if (empty($mail)) {
            $attributeName = $this->getUserMailSAMLAttributeName();

            Yii::app()->session['AuthSAML_configuration_error'] = true;

            $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('Required SAML attribute missing'));

            $this->log(__METHOD__." - ERROR: Missing required attribute '$attributeName' in SAML response.", \CLogger::LEVEL_ERROR);
            $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
            return;
        }


        $user_access_group = $this->get('user_access_group');
        if (!empty($user_access_group)) {
            $user_access = false;
            if ( is_array($usergroup) ) {
                foreach ($usergroup as $key => $value) {
                    // For example: "ls" or "ls,admin" or "ADLDS CN=G-APP-5650-LimeSurvey,OU=H-5600-APP,OU=TestAD,O=TestAD-AD"
                    $group = $value;
                    if (strpos($value, ',') !== false) {
                        $group_array = explode(',', $value);
                        $group = $group_array[0];
                    }

                    if (strpos($group, '=') !== false) {
                        $group_array = explode('=', $group);
                        $group = $group_array[1];
                    }

                    if ($group == $user_access_group) {
                        $user_access = true;
                        break;
                    }
                }
            }

            if (!$user_access) {

                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('You have no access'));

                $this->log(__METHOD__.' - ERROR', \CLogger::LEVEL_ERROR);
                $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

                return;
            }
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

            // If user cannot login via SAML: setAuthFailure
            if (($oUser->uid == 1 && !$this->get('allowInitialUser'))
                || !Permission::model()->hasGlobalPermission('auth_saml', 'read', $oUser->uid))
            {
                $this->log(__METHOD__.' - ERROR: authentication method is not allowed for this user: '.$oUser->uid, \CLogger::LEVEL_ERROR);
                $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);

                $this->setAuthFailure(self::ERROR_AUTH_METHOD_INVALID, gT('SAML authentication method is not allowed for this user'));
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

            $this->setAuthSuccess($oUser);
            $this->log(__METHOD__.' - User updated: '.$oUser->uid, \CLogger::LEVEL_TRACE);
        }
        $this->log(__METHOD__.' - END', \CLogger::LEVEL_TRACE);
    }

    private function assignUserPermissions(string $uid)
    {
        Permission::model()->setGlobalPermission($uid, 'auth_saml');

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

    /**
     * Initialize SAML authentication
     * @return void
     */
    public function get_saml_instance() {

        if ($this->ssp == null) {

            $simplesamlphp_path = $this->get('simplesamlphp_path', null, null, $this->settings['simplesamlphp_path']['default']);

            // To avoid __autoload conflicts, remove limesurvey autoloads temporarily
            $autoload_functions = spl_autoload_functions();
            foreach ($autoload_functions as $function) {
                spl_autoload_unregister($function);
            }

            require_once($simplesamlphp_path.'/lib/_autoload.php');

            $saml_authsource = $this->get('saml_authsource', null, null, $this->settings['saml_authsource']['default']);

            if (class_exists('\SimpleSAML\Auth\Simple')) {
                $this->ssp = new \SimpleSAML\Auth\Simple($saml_authsource);
            }

            // To avoid __autoload conflicts, restote the limesurvey autoloads
            foreach ($autoload_functions as $function) {
                spl_autoload_register($function);
            }
        }

        return $this->ssp;
    }

    public function getUserNameSAML()
    {
        return $this->getSAMLAttribute($this->getUserNameSAMLAttributeName());
    }

    public function getUserNameSAMLAttributeName()
    {
        return $this->get('saml_uid_mapping', null, null, $this->settings['saml_uid_mapping']['default']);
    }

    public function getSAMLAttribute(string $attribute_name)
    {
        $attributeValue = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();

        if (!empty($attributes)) {
            if (array_key_exists($attribute_name, $attributes) && !empty($attributes[$attribute_name]))	{
                $attributeValue = $attributes[$attribute_name][0];
            }
        }
        return $attributeValue;
    }

    public function getUserCommonName()
    {
        return $this->getSAMLAttribute($this->getUserCommonNameSAMLAttributeName());
    }

    private function getUserCommonNameSAMLAttributeName()
    {
        return $this->get('saml_name_mapping', null, null, $this->settings['saml_name_mapping']['default']);
    }

    public function getUserMail()
    {
        return $this->getSAMLAttribute($this->getUserMailSAMLAttributeName());
    }

    private function getUserMailSAMLAttributeName()
    {
        return $this->get('saml_mail_mapping', null, null, $this->settings['saml_mail_mapping']['default']);
    }

    private function getUserGroup()
    {
        return $this->getSAMLAttribute($this->getUserGroupSAMLAttributeName());
    }

    private function getUserGroupSAMLAttributeName()
    {
        return $this->get('saml_group_mapping', null, null, $this->settings['saml_group_mapping']['default']);
    }
}
