<?php
/**
 * Storage helpers: event log table and snapshot options.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * One event table (logins, blocks, alerts, quarantine) plus a few options for report snapshots.
 */
final class Store {

	/**
	 * Event table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'index_sentinel_log';
	}

	/**
	 * Write one event.
	 *
	 * @param string $type     Event type slug.
	 * @param string $message  Human message.
	 * @param string $severity info|notice|warning|critical.
	 * @param array  $context  Extra data.
	 * @param string $ip       Visitor IP (defaults to the current request).
	 */
	public static function log( $type, $message, $severity = 'info', $context = array(), $ip = '' ) {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			self::table(),
			array(
				'type'       => substr( $type, 0, 30 ),
				'severity'   => $severity,
				'ip'         => $ip ? $ip : self::ip(),
				'message'    => $message,
				'context'    => $context ? wp_json_encode( $context ) : null,
				'created_at' => current_time( 'mysql', true ),
			)
		);
	}

	/**
	 * Latest events.
	 *
	 * @param array $types Types to include (empty = all).
	 * @param int   $limit Max rows.
	 * @return array
	 */
	public static function events( $types = array(), $limit = 50 ) {
		global $wpdb;
		$table = self::table();
		if ( $types ) {
			$in   = implode( ',', array_fill( 0, count( $types ), '%s' ) );
			$args = array_merge( $types, array( (int) $limit ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
			return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE type IN ({$in}) ORDER BY id DESC LIMIT %d", $args ), ARRAY_A );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", (int) $limit ), ARRAY_A );
	}

	/**
	 * Count events of a type since a GMT datetime.
	 *
	 * @param string $type  Event type.
	 * @param string $since GMT 'Y-m-d H:i:s'.
	 * @param string $ip    Optional IP filter.
	 * @return int
	 */
	public static function count( $type, $since, $ip = '' ) {
		global $wpdb;
		$table = self::table();
		if ( $ip ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE type = %s AND created_at >= %s AND ip = %s", $type, $since, $ip ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE type = %s AND created_at >= %s", $type, $since ) );
	}

	/**
	 * Delete events older than 90 days.
	 */
	public static function prune() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", gmdate( 'Y-m-d H:i:s', strtotime( '-90 days' ) ) ) );
	}

	/**
	 * Read a snapshot option.
	 *
	 * @param string $key     Key without prefix.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	public static function get( $key, $default = array() ) {
		return get_option( 'index_sentinel_' . $key, $default );
	}

	/**
	 * Save a snapshot option (never autoloaded).
	 *
	 * @param string $key   Key without prefix.
	 * @param mixed  $value Value.
	 */
	public static function set( $key, $value ) {
		update_option( 'index_sentinel_' . $key, $value, false );
	}

	/**
	 * Visitor IP. Cloudflare's header is trusted only when the connection itself comes from Cloudflare.
	 *
	 * @return string
	 */
	public static function ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$cf     = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';
		if ( $cf && filter_var( $cf, FILTER_VALIDATE_IP ) && Settings::get( 'trust_cloudflare' ) && self::is_cloudflare( $remote ) ) {
			return $cf;
		}
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';
	}

	/**
	 * Is the IP inside Cloudflare's published ranges?
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_cloudflare( $ip ) {
		$ranges = array(
			'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
			'190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
			'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
			'2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
		);
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $bin ) {
			return false;
		}
		foreach ( $ranges as $cidr ) {
			list( $net, $bits ) = explode( '/', $cidr );
			$net_bin            = inet_pton( $net );
			if ( strlen( $net_bin ) !== strlen( $bin ) ) {
				continue;
			}
			$bytes = intdiv( (int) $bits, 8 );
			$rest  = (int) $bits % 8;
			if ( substr( $bin, 0, $bytes ) !== substr( $net_bin, 0, $bytes ) ) {
				continue;
			}
			if ( ! $rest || ( ord( $bin[ $bytes ] ) >> ( 8 - $rest ) ) === ( ord( $net_bin[ $bytes ] ) >> ( 8 - $rest ) ) ) {
				return true;
			}
		}
		return false;
	}
}
