<?php
/**
 * Uninstall: remove data only if the user asked for it in Settings.
 *
 * @package IndexSentinel
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

wp_clear_scheduled_hook( 'index_sentinel_daily' );
wp_clear_scheduled_hook( 'index_sentinel_hourly' );

$index_sentinel_settings = get_option( 'index_sentinel_settings', array() );
if ( empty( $index_sentinel_settings['delete_on_uninstall'] ) ) {
	return;
}

global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}index_sentinel_log" );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'index\\_sentinel\\_%' OR option_name LIKE '\\_transient\\_index\\_sentinel\\_%' OR option_name LIKE '\\_transient\\_timeout\\_index\\_sentinel\\_%'" );
