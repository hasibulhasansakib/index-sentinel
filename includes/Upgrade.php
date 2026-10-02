<?php
/**
 * Database install and versioned upgrades.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * Keeps the schema in step with the code. Bump DB_VERSION and add a step in maybe_upgrade()
 * whenever a future release changes storage, so updates from the WordPress dashboard migrate safely.
 */
final class Upgrade {

	const DB_VERSION = 1;

	/**
	 * Create or update the event log table.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = Store::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			type varchar(30) NOT NULL,
			severity varchar(10) NOT NULL DEFAULT 'info',
			ip varchar(45) NOT NULL DEFAULT '',
			message text NOT NULL,
			context longtext NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY type_created (type, created_at),
			KEY ip (ip)
		) {$charset};"
		);
		update_option( 'index_sentinel_db_version', self::DB_VERSION, false );
		if ( false === get_option( 'index_sentinel_settings' ) ) {
			update_option( 'index_sentinel_settings', Settings::defaults(), false );
		}
	}

	/**
	 * Run pending upgrade steps after a plugin update (activation hooks do not fire on updates).
	 */
	public static function maybe_upgrade() {
		$installed = (int) get_option( 'index_sentinel_db_version', 0 );
		if ( $installed >= self::DB_VERSION ) {
			return;
		}
		self::install();
		// Future steps go here, e.g. if ( $installed < 2 ) { ... }.
	}
}
