<?php
/**
 * Lightweight request filter.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Runs early on front-end requests:
 * - URLs matching your spam patterns answer "410 Gone" (optional), which tells Google to drop them for good.
 * - Obvious exploit probes (secret files, web shells, path traversal, SQL injection strings) get "403 Forbidden".
 */
final class Firewall {

	/**
	 * Probe patterns. Each is matched against the decoded request URI.
	 *
	 * @return string[]
	 */
	private function probes() {
		$probes = array(
			'#/\.(env|git|svn|htpasswd|aws)(/|$)#i',
			'#/(wso|c99|r57|alfa|shell|cmd|uploader)\.php$#i',
			'#\.\./\.\./#',
			'#(union(\s|\+)+select|information_schema|sleep\(\d+\)|benchmark\()#i',
			'#<script#i',
			'#/(wp-config\.php\.(bak|old|save|txt|orig)|phpinfo\.php|adminer\.php)#i',
		);
		/**
		 * Filter the firewall probe patterns.
		 *
		 * @param string[] $probes Regular expressions.
		 */
		return (array) apply_filters( 'index_sentinel_firewall_probes', $probes );
	}

	/**
	 * Check the current request.
	 */
	public function init() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || is_admin() ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$raw  = isset( $_SERVER['REQUEST_URI'] ) ? rawurldecode( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only pattern-matched, never output or stored unescaped.
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );

		if ( Settings::get( 'spam_410' ) && Settings::is_spam_path( $path ) ) {
			$this->stop( 410, '' );
		}
		foreach ( $this->probes() as $re ) {
			if ( preg_match( $re, $raw ) ) {
				$this->stop( 403, $uri );
			}
		}
	}

	/**
	 * End the request.
	 *
	 * @param int    $code HTTP status.
	 * @param string $uri  Request URI to log (403 only).
	 */
	private function stop( $code, $uri ) {
		if ( 403 === $code ) {
			$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 200 ) : '';
			Store::log( 'blocked', __( 'Exploit probe blocked', 'index-sentinel' ), 'warning', array( 'uri' => substr( $uri, 0, 300 ), 'ua' => $ua ) );
		}
		status_header( $code );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html( 410 === $code ? __( 'This page has been permanently removed.', 'index-sentinel' ) : __( 'Forbidden.', 'index-sentinel' ) );
		exit;
	}
}
