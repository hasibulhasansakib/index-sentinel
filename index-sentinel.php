<?php
/**
 * Plugin Name:       Index Sentinel – SEO Spam & Malware Monitor
 * Plugin URI:        https://hasibulhasansakib.com/plugins/index-sentinel/
 * Description:       Catch SEO spam hacks before Google does. Malware and file-integrity scans, a Googlebot cloaking check, Google index monitoring, spam URL clean-up tracking, login protection and email alerts in one clear dashboard.
 * Version:           1.0.0
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Hasibul Hasan Sakib
 * Author URI:        https://hasibulhasansakib.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       index-sentinel
 * Domain Path:       /languages
 *
 * @package IndexSentinel
 */

defined( 'ABSPATH' ) || exit;

define( 'INDEX_SENTINEL_VERSION', '1.0.0' );
define( 'INDEX_SENTINEL_FILE', __FILE__ );
define( 'INDEX_SENTINEL_DIR', plugin_dir_path( __FILE__ ) );
define( 'INDEX_SENTINEL_URL', plugin_dir_url( __FILE__ ) );

/*
 * PSR-4 style autoloader: IndexSentinel\Admin\Dashboard -> includes/Admin/Dashboard.php
 */
spl_autoload_register(
	static function ( $class ) {
		$prefix = 'IndexSentinel\\';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}
		$file = INDEX_SENTINEL_DIR . 'includes/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		if ( is_readable( $file ) ) {
			require $file;
		}
	}
);

register_activation_hook( __FILE__, array( 'IndexSentinel\\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'IndexSentinel\\Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'IndexSentinel\\Plugin', 'instance' ), 5 );
