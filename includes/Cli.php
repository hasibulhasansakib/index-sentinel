<?php
/**
 * WP-CLI commands.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * Run Index Sentinel jobs from the command line.
 *
 * ## EXAMPLES
 *
 *     wp index-sentinel scan
 *     wp index-sentinel google
 *     wp index-sentinel traffic
 *     wp index-sentinel cloak
 *     wp index-sentinel daily
 *     wp index-sentinel accept-baseline
 */
final class Cli {

	/**
	 * Run the malware and integrity scan.
	 */
	public function scan() {
		$r = ( new Modules\Scanner() )->run();
		\WP_CLI::log( sprintf( '%d files in %ss, %d findings', $r['files'], $r['duration'], count( $r['findings'] ) ) );
		foreach ( $r['findings'] as $f ) {
			\WP_CLI::log( "[{$f['severity']}] {$f['type']} {$f['path']} - {$f['detail']}" );
		}
	}

	/**
	 * Read the server access logs.
	 */
	public function traffic() {
		$r = ( new Modules\LogReader() )->run();
		\WP_CLI::log( isset( $r['error'] ) ? $r['error'] : wp_json_encode( array_slice( $r['days'], -7, null, true ) ) );
	}

	/**
	 * Refresh Search Console data (needs Site Kit).
	 */
	public function google() {
		$r = ( new Modules\Google() )->refresh();
		if ( isset( $r['error'] ) ) {
			\WP_CLI::warning( $r['error'] );
			return;
		}
		\WP_CLI::log( sprintf( '%d URLs, %d unknown URLs with impressions, %d known spam URLs still shown', count( $r['urls'] ), count( $r['analytics']['unknown'] ), $r['analytics']['spam_count'] ) );
	}

	/**
	 * Googlebot cloaking check.
	 */
	public function cloak() {
		$r = ( new Modules\Scanner() )->cloaking_check();
		Store::set( 'cloak', $r );
		\WP_CLI::log( wp_json_encode( $r ) );
	}

	/**
	 * Run the full daily job now.
	 */
	public function daily() {
		Plugin::instance()->run_daily();
		\WP_CLI::success( 'Daily job done.' );
	}

	/**
	 * Mark the current files as trusted.
	 *
	 * @subcommand accept-baseline
	 */
	public function accept_baseline() {
		Modules\Scanner::accept_baseline();
		\WP_CLI::success( 'Current files accepted as trusted.' );
	}
}
