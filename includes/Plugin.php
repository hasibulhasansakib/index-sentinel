<?php
/**
 * Main plugin class: boots modules, owns cron jobs and database upgrades.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * Plugin bootstrap.
 *
 * Extension points for add-ons (for example a future Pro add-on):
 * - action `index_sentinel_loaded` (Plugin $plugin) after everything is wired.
 * - filter `index_sentinel_daily_jobs` to add work to the daily run.
 * - see Admin\Dashboard for `index_sentinel_tabs` and Scanner for `index_sentinel_signatures`.
 */
final class Plugin {

	/**
	 * Single instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Get (and on first call, boot) the plugin.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire modules and hooks.
	 */
	private function __construct() {
		Upgrade::maybe_upgrade();

		$settings = Settings::all();
		if ( ! empty( $settings['module_firewall'] ) ) {
			( new Modules\Firewall() )->init();
		}
		if ( ! empty( $settings['module_login'] ) ) {
			( new Modules\LoginGuard() )->init();
		}
		( new Modules\Hardening() )->init();

		add_action( 'index_sentinel_daily', array( $this, 'run_daily' ) );
		add_action( 'index_sentinel_hourly', array( $this, 'run_hourly' ) );

		if ( is_admin() ) {
			( new Admin\Dashboard() )->init();
			add_filter( 'plugin_action_links_' . plugin_basename( INDEX_SENTINEL_FILE ), array( $this, 'action_links' ) );
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'index-sentinel', Cli::class );
		}

		/**
		 * Fires when Index Sentinel is fully loaded.
		 *
		 * @param Plugin $plugin Plugin instance.
		 */
		do_action( 'index_sentinel_loaded', $this );
	}

	/**
	 * Activation: tables, defaults, schedules.
	 */
	public static function activate() {
		Upgrade::install();
		if ( ! wp_next_scheduled( 'index_sentinel_daily' ) ) {
			wp_schedule_event( strtotime( 'tomorrow 03:30' ), 'daily', 'index_sentinel_daily' );
		}
		if ( ! wp_next_scheduled( 'index_sentinel_hourly' ) ) {
			wp_schedule_event( time() + 10 * MINUTE_IN_SECONDS, 'hourly', 'index_sentinel_hourly' );
		}
	}

	/**
	 * Deactivation: stop schedules, keep data.
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'index_sentinel_daily' );
		wp_clear_scheduled_hook( 'index_sentinel_hourly' );
	}

	/**
	 * Daily job: full scan, logs, Google, then one alert email if something new and serious turned up.
	 */
	public function run_daily() {
		$settings = Settings::all();
		$scan     = ! empty( $settings['module_scanner'] ) ? ( new Modules\Scanner() )->run() : array();
		$traffic  = ! empty( $settings['module_traffic'] ) ? ( new Modules\LogReader() )->run() : array();
		$google   = ( ! empty( $settings['module_google'] ) && Modules\Google::available() ) ? ( new Modules\Google() )->refresh() : array();
		( new Alerts() )->daily( $scan, $traffic, $google );
		Store::prune();

		/**
		 * Extra daily work for add-ons.
		 *
		 * @param array $scan    Scan result.
		 * @param array $traffic Traffic result.
		 * @param array $google  Google result.
		 */
		do_action( 'index_sentinel_daily_jobs', $scan, $traffic, $google );
	}

	/**
	 * Hourly job: the Googlebot cloaking check is cheap and catches a reinfection fast.
	 */
	public function run_hourly() {
		if ( empty( Settings::get( 'module_cloaking' ) ) ) {
			return;
		}
		$cloak = ( new Modules\Scanner() )->cloaking_check();
		Store::set( 'cloak', $cloak );
		if ( ! empty( $cloak['problems'] ) ) {
			( new Alerts() )->send_once(
				'cloak-' . md5( wp_json_encode( $cloak['problems'] ) ),
				__( 'Spam content is being shown to Google', 'index-sentinel' ),
				$cloak['problems']
			);
		}
	}

	/**
	 * "Dashboard | Settings" links on the Plugins screen.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift(
			$links,
			'<a href="' . esc_url( admin_url( 'admin.php?page=index-sentinel' ) ) . '">' . esc_html__( 'Dashboard', 'index-sentinel' ) . '</a>',
			'<a href="' . esc_url( admin_url( 'admin.php?page=index-sentinel&tab=settings' ) ) . '">' . esc_html__( 'Settings', 'index-sentinel' ) . '</a>'
		);
		return $links;
	}
}
