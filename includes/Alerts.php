<?php
/**
 * Email alerts.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * Each distinct problem is emailed once (by fingerprint), so the daily run never floods the inbox.
 */
final class Alerts {

	/**
	 * Build and send the daily alert, if anything serious is new.
	 *
	 * @param array $scan    Scan result.
	 * @param array $traffic Traffic result.
	 * @param array $google  Google result.
	 */
	public function daily( $scan, $traffic, $google ) {
		$lines = array();
		foreach ( isset( $scan['findings'] ) ? $scan['findings'] : array() as $f ) {
			if ( 'critical' === $f['severity'] ) {
				$lines[] = sprintf( '[%s] %s: %s', __( 'Malware/integrity', 'index-sentinel' ), $f['path'], $f['detail'] );
			}
		}
		foreach ( isset( $google['analytics']['unknown'] ) ? $google['analytics']['unknown'] : array() as $u ) {
			if ( $u['impressions'] >= 3 ) {
				/* translators: 1: URL, 2: impressions. */
				$lines[] = sprintf( __( '[Google] Unknown URL is getting impressions: %1$s (%2$d impressions). Check that it is yours.', 'index-sentinel' ), $u['url'], $u['impressions'] );
			}
		}
		$yesterday = gmdate( 'Y-m-d', strtotime( '-1 day' ) );
		if ( ! empty( $traffic['days'][ $yesterday ]['probes'] ) && $traffic['days'][ $yesterday ]['probes'] > 500 ) {
			/* translators: %d: number of probe requests. */
			$lines[] = sprintf( __( '[Traffic] %d hacker probe requests yesterday.', 'index-sentinel' ), $traffic['days'][ $yesterday ]['probes'] );
		}
		if ( $lines ) {
			$this->send_once( 'daily-' . md5( implode( '|', $lines ) ), __( 'Security findings need your attention', 'index-sentinel' ), $lines );
		}
	}

	/**
	 * Send unless this exact problem was already sent.
	 *
	 * @param string $fingerprint Unique key.
	 * @param string $subject     Subject.
	 * @param array  $lines       Body lines.
	 */
	public function send_once( $fingerprint, $subject, $lines ) {
		$sent = Store::get( 'alerts_sent', array() );
		if ( isset( $sent[ $fingerprint ] ) ) {
			return;
		}
		$this->send_now( $subject, $lines );
		$sent[ $fingerprint ] = time();
		Store::set( 'alerts_sent', array_slice( $sent, -200, null, true ) );
	}

	/**
	 * Send now and log it.
	 *
	 * @param string $subject Subject.
	 * @param array  $lines   Body lines.
	 */
	public function send_now( $subject, $lines ) {
		Store::log( 'alert', $subject, 'critical', array( 'lines' => $lines ) );
		if ( ! Settings::get( 'alerts' ) ) {
			return;
		}
		$site = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		/* translators: %s: site domain. */
		$body = sprintf( __( 'Index Sentinel found something on %s:', 'index-sentinel' ), $site ) . "\n\n- " . implode( "\n- ", $lines )
			. "\n\n" . __( 'Open the dashboard:', 'index-sentinel' ) . ' ' . admin_url( 'admin.php?page=index-sentinel' ) . "\n";
		wp_mail( Settings::get( 'alert_email' ), '[' . $site . '] ' . $subject, $body );
	}
}
