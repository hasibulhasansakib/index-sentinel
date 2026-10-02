<?php
/**
 * Plugin settings with defaults and sanitising.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel;

defined( 'ABSPATH' ) || exit;

/**
 * Settings live in one option. Every module can be switched off.
 */
final class Settings {

	/**
	 * Pattern used by the common "Japanese keyword hack" (example: /word/word/abc123xyz.html).
	 */
	const JAPANESE_HACK_PATTERN = '#^/[a-z]+/[a-z]+/[a-z0-9]{8,}\.html$#';

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Default values.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'module_scanner'    => 1,
			'module_cloaking'   => 1,
			'module_google'     => 1,
			'module_traffic'    => 1,
			'module_firewall'   => 1,
			'module_login'      => 1,
			'alert_email'       => get_option( 'admin_email' ),
			'alerts'            => 1,
			'max_attempts'      => 5,
			'lockout_minutes'   => 30,
			'trust_cloudflare'  => 1,
			'spam_patterns'     => '',
			'spam_410'          => 0,
			'log_path'          => '',
			'harden_users_api'  => 1,
			'harden_author'     => 1,
			'harden_xmlrpc'     => 1,
			'harden_version'    => 1,
			'harden_login_msg'  => 1,
			'delete_on_uninstall' => 0,
		);
	}

	/**
	 * All settings merged with defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$saved       = get_option( 'index_sentinel_settings', array() );
			self::$cache = wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
		}
		return self::$cache;
	}

	/**
	 * One setting.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Spam URL patterns as a list of valid regular expressions.
	 *
	 * @return string[]
	 */
	public static function spam_patterns() {
		$lines = preg_split( '/\r\n|\r|\n/', (string) self::get( 'spam_patterns' ) );
		$out   = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' !== $line && self::valid_regex( $line ) ) {
				$out[] = $line;
			}
		}
		/**
		 * Filter the spam URL patterns (regular expressions matched against the URL path).
		 *
		 * @param string[] $out Patterns.
		 */
		return (array) apply_filters( 'index_sentinel_spam_patterns', $out );
	}

	/**
	 * Does a URL path match any spam pattern?
	 *
	 * @param string $path URL path.
	 * @return bool
	 */
	public static function is_spam_path( $path ) {
		// Match against the path inside the site, so WordPress in a sub-folder (/blog/...) works too.
		$base = untrailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) );
		if ( $base && 0 === strpos( $path, $base . '/' ) ) {
			$path = substr( $path, strlen( $base ) );
		}
		foreach ( self::spam_patterns() as $re ) {
			if ( preg_match( $re, $path ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is the string a usable regular expression?
	 *
	 * @param string $re Pattern.
	 * @return bool
	 */
	public static function valid_regex( $re ) {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return false !== @preg_match( $re, '' );
	}

	/**
	 * Sanitise and save posted settings.
	 *
	 * @param array $input Raw input (already unslashed).
	 */
	public static function save( $input ) {
		$s = self::all();
		foreach ( array( 'module_scanner', 'module_cloaking', 'module_google', 'module_traffic', 'module_firewall', 'module_login', 'alerts', 'trust_cloudflare', 'spam_410', 'harden_users_api', 'harden_author', 'harden_xmlrpc', 'harden_version', 'harden_login_msg', 'delete_on_uninstall' ) as $flag ) {
			$s[ $flag ] = empty( $input[ $flag ] ) ? 0 : 1;
		}
		$email              = sanitize_email( isset( $input['alert_email'] ) ? $input['alert_email'] : '' );
		$s['alert_email']   = $email ? $email : $s['alert_email'];
		$s['max_attempts']  = max( 3, min( 20, (int) ( isset( $input['max_attempts'] ) ? $input['max_attempts'] : 5 ) ) );
		$s['lockout_minutes'] = max( 5, min( 1440, (int) ( isset( $input['lockout_minutes'] ) ? $input['lockout_minutes'] : 30 ) ) );
		$s['log_path']      = sanitize_text_field( isset( $input['log_path'] ) ? $input['log_path'] : '' );

		$patterns = array();
		foreach ( preg_split( '/\r\n|\r|\n/', isset( $input['spam_patterns'] ) ? (string) $input['spam_patterns'] : '' ) as $line ) {
			$line = trim( wp_strip_all_tags( $line ) );
			if ( '' !== $line && self::valid_regex( $line ) ) {
				$patterns[] = $line;
			}
		}
		$s['spam_patterns'] = implode( "\n", array_unique( $patterns ) );

		update_option( 'index_sentinel_settings', $s, false );
		self::$cache = null;
	}
}
