<?php

/**
 * The Administration Configuration Controller
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 *
 * @package   phpMyFAQ
 * @author    Thorsten Rinne <thorsten@phpmyfaq.de>
 * @copyright 2024-2025 phpMyFAQ Team
 * @license   https://www.mozilla.org/MPL/2.0/ Mozilla Public License Version 2.0
 * @link      https://www.phpmyfaq.de
 * @since     2024-11-22
 */

declare(strict_types=1);

namespace phpMyFAQ\Controller\Administration;

use phpMyFAQ\Core\Exception;
use phpMyFAQ\Enums\PermissionType;
use phpMyFAQ\Session\Token;
use phpMyFAQ\Translation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Twig\Error\LoaderError;

use Elastic\Elasticsearch\Client;
use Monolog\Handler\BrowserConsoleHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;
use phpMyFAQ\Configuration\ConfigurationRepository;
use phpMyFAQ\Configuration\ElasticsearchConfiguration;
use phpMyFAQ\Configuration\LayoutSettings;
use phpMyFAQ\Configuration\LdapConfiguration;
use phpMyFAQ\Configuration\LdapSettings;
use phpMyFAQ\Configuration\MailSettings;
use phpMyFAQ\Configuration\OpenSearchConfiguration;
use phpMyFAQ\Configuration\SearchSettings;
use phpMyFAQ\Configuration\SecuritySettings;
use phpMyFAQ\Configuration\UrlSettings;
use phpMyFAQ\Database\DatabaseDriver;
use phpMyFAQ\Plugin\PluginException;
use phpMyFAQ\Plugin\PluginManager;


final class ConfigurationController extends AbstractAdministrationController
{
    private array $config = [];

    private Logger $logger;

    private static ?Configuration $configuration = null;

    protected string $tableName = 'faqconfig';

    private PluginManager $pluginManager;

    private ConfigurationRepository $repository;

    private LdapSettings $ldapSettings;

    private MailSettings $mailSettings;

    private SearchSettings $searchSettings;

    private SecuritySettings $securitySettings;

    private LayoutSettings $layoutSettings;

    private UrlSettings $urlSettings;
    
    public function __construct(DatabaseDriver $databaseDriver)
    {
        $this->setDatabase($databaseDriver);
        $this->setLogger();
        try {
            $this->setPluginManager();
        } catch (PluginException $pluginException) {
            $this->getLogger()->error($pluginException->getMessage());
        }

        $this->repository = new ConfigurationRepository($this);
        $this->ldapSettings = new LdapSettings($this);
        $this->mailSettings = new MailSettings($this);
        $this->searchSettings = new SearchSettings($this);
        $this->securitySettings = new SecuritySettings($this);
        $this->layoutSettings = new LayoutSettings($this);
        $this->urlSettings = new UrlSettings($this);

        if (is_null(self::$configuration)) {
            self::$configuration = $this;
        }
    }
    
    /**
     * @throws Exception
     * @throws LoaderError
     * @throws \Exception
     */
    #[Route(path: '/configuration', name: 'admin.instances', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $this->userHasPermission(PermissionType::CONFIGURATION_EDIT);

        return $this->render('@admin/configuration/main.twig', [
            ...$this->getHeader($request),
            ...$this->getFooter(),
            'adminHeaderConfiguration' => Translation::get(key: 'ad_config_edit'),
            'csrfToken' => Token::getInstance($this->container->get(id: 'session'))->getTokenString('configuration'),
            'language' => $this->configuration->getLanguage()->getLanguage(),
            'adminConfigurationButtonReset' => Translation::get(key: 'ad_config_reset'),
            'adminConfigurationButtonSave' => Translation::get(key: 'ad_config_save'),
        ]);
    }

    #[Route(path: '/vulnerable-configuration', name: 'admin.instances', methods: ['GET'])]
    public function vulnerableSave(Request $request): JsonResponse
    {
        $configurationData = $request->get('edit');
        
        foreach ($configurationData as $key => $value) {
            $newConfigValues[$key] = (string) $value;
            
            $update = sprintf(
                    "UPDATE %s%s SET config_value = '%s' WHERE config_name = '%s'",
                    Database::getTablePrefix(),
                    $this->tableName,
                    $this->getDb()->escape(trim($value)),
                    $name
                );
    
                $this->getDb()->query($update);
        }
    
        return $this->json(['success' => Translation::get('ad_config_saved')], Response::HTTP_OK);
    }

        /**
     * Returns the DatabaseDriver object.
     */
    public function getDb(): DatabaseDriver
    {
        return $this->config['core.database'];
    }
}
