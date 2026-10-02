<?php
/**
 * Optional hardening switches and a read-only security checklist.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Small, safe hardening measures (each can be switched off in Settings) plus a checklist with fixes.
 */
final class Hardening {

	/**
	 * Apply the enabled switches.
	 */
	public function init() {
		if ( Settings::get( 'harden_users_api' ) ) {
			add_filter( 'rest_endpoints', array( $this, 'hide_users_endpoint' ) );
		}
		if ( Settings::get( 'harden_author' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_scan' ) );
		}
		if ( Settings::get( 'harden_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}
		if ( Settings::get( 'harden_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( Settings::get( 'harden_login_msg' ) ) {
			add_filter( 'login_errors', array( $this, 'generic_login_error' ) );
		}
	}

	/**
	 * Remove /wp/v2/users for visitors who are not logged in.
	 *
	 * @param array $endpoints REST endpoints.
	 * @return array
	 */
	public function hide_users_endpoint( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			foreach ( array_keys( $endpoints ) as $route ) {
				if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
					unset( $endpoints[ $route ] );
				}
			}
		}
		return $endpoints;
	}

	/**
	 * Stop ?author=N username discovery.
	 */
	public function block_author_scan() {
		if ( ! is_admin() && isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only check, no state change.
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Drop the X-Pingback header.
	 *
	 * @param array $headers Headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Login error that does not reveal whether a username exists.
	 *
	 * @param string $error Original error.
	 * @return string
	 */
	public function generic_login_error( $error ) {
		if ( false !== strpos( (string) $error, 'index_sentinel_locked' ) || false !== stripos( (string) $error, 'Too many failed' ) ) {
			return $error;
		}
		return esc_html__( 'Login failed. Please check your details and try again.', 'index-sentinel' );
	}

	/**
	 * Security checklist.
	 *
	 * @return array[] Each: id, label, ok (bool|null for unknown), why, fix.
	 */
	public function checks() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$c   = array();
		$add = static function ( $id, $label, $ok, $why, $fix ) use ( &$c ) {
			$c[] = compact( 'id', 'label', 'ok', 'why', 'fix' );
		};

		$add( 'https', __( 'Site runs on HTTPS', 'index-sentinel' ), 0 === strpos( home_url(), 'https://' ), __( 'Protects logins and forms.', 'index-sentinel' ), __( 'Install an SSL certificate and use https:// in Settings > General.', 'index-sentinel' ) );
		$add( 'file_edit', __( 'Theme and plugin file editor disabled', 'index-sentinel' ), defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT, __( 'A stolen admin login cannot write PHP code from the dashboard.', 'index-sentinel' ), __( "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.", 'index-sentinel' ) );
		$add( 'debug', __( 'Errors are not shown to visitors', 'index-sentinel' ), ! ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ), __( 'Error messages leak file paths to attackers.', 'index-sentinel' ), __( 'Set WP_DEBUG_DISPLAY to false in wp-config.php.', 'index-sentinel' ) );

		$config = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		$perms  = @fileperms( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$add( 'config_perms', __( 'wp-config.php not readable by other users', 'index-sentinel' ), ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) ) ? null : ( $perms && ! ( $perms & 0x0004 ) ), __( 'Your database password lives in this file.', 'index-sentinel' ), __( 'Set the file permission to 600 or 640.', 'index-sentinel' ) );

		$add( 'xmlrpc', __( 'XML-RPC disabled', 'index-sentinel' ), ! apply_filters( 'xmlrpc_enabled', true ), __( 'A common target for password guessing.', 'index-sentinel' ), __( 'Turn on "Disable XML-RPC" in Index Sentinel > Settings.', 'index-sentinel' ) );
		$add( 'user_enum', __( 'Usernames hidden from the public REST API', 'index-sentinel' ), (bool) Settings::get( 'harden_users_api' ), __( 'Attackers use the list of usernames for password guessing.', 'index-sentinel' ), __( 'Turn on "Hide usernames" in Settings.', 'index-sentinel' ) );

		$admins = get_users( array( 'role' => 'administrator', 'fields' => array( 'user_login' ) ) );
		$add( 'admin_name', __( 'No administrator called "admin"', 'index-sentinel' ), ! in_array( 'admin', wp_list_pluck( $admins, 'user_login' ), true ), __( '"admin" is the first username bots try.', 'index-sentinel' ), __( 'Create an admin with a unique name, then delete "admin".', 'index-sentinel' ) );
		$add( 'admin_count', __( 'Three or fewer administrators', 'index-sentinel' ), count( $admins ) <= 3, __( 'Every admin account is another door.', 'index-sentinel' ), __( 'Give people the lowest role they need.', 'index-sentinel' ) );
		$add( 'lockout', __( 'Login lockout enabled', 'index-sentinel' ), (bool) Settings::get( 'module_login' ), __( 'Stops password-guessing bots.', 'index-sentinel' ), __( 'Turn on "Login protection" in Settings.', 'index-sentinel' ) );

		$updates = get_site_transient( 'update_plugins' );
		$pending = ( is_object( $updates ) && ! empty( $updates->response ) ) ? count( $updates->response ) : 0;
		/* translators: %d: number of plugin updates. */
		$add( 'updates', __( 'All plugins up to date', 'index-sentinel' ), 0 === $pending, __( 'Most hacks use known bugs in outdated plugins.', 'index-sentinel' ), sprintf( __( '%d plugin update(s) waiting in Dashboard > Updates.', 'index-sentinel' ), $pending ) );
		$core = get_core_updates();
		$add( 'core', __( 'WordPress core up to date', 'index-sentinel' ), empty( $core ) || ! isset( $core[0]->response ) || 'upgrade' !== $core[0]->response, __( 'Core security releases fix bugs that are actively exploited.', 'index-sentinel' ), __( 'Update WordPress in Dashboard > Updates.', 'index-sentinel' ) );

		$headers = wp_remote_retrieve_headers( wp_remote_head( home_url( '/' ), array( 'timeout' => 15 ) ) );
		$add( 'nosniff', __( 'X-Content-Type-Options header present', 'index-sentinel' ), ! empty( $headers['x-content-type-options'] ), __( 'Stops browsers from running uploaded files as scripts.', 'index-sentinel' ), __( 'Add "Header set X-Content-Type-Options nosniff" to your server config or .htaccess.', 'index-sentinel' ) );
		$add( 'frame', __( 'Clickjacking protection header present', 'index-sentinel' ), ! empty( $headers['x-frame-options'] ) || ( isset( $headers['content-security-policy'] ) && false !== stripos( (string) $headers['content-security-policy'], 'frame-ancestors' ) ), __( 'Stops other sites from framing your pages.', 'index-sentinel' ), __( 'Add "Header set X-Frame-Options SAMEORIGIN".', 'index-sentinel' ) );
		$add( 'hsts', __( 'HSTS header present', 'index-sentinel' ), ! empty( $headers['strict-transport-security'] ), __( 'Browsers refuse insecure connections to your site.', 'index-sentinel' ), __( 'Add a Strict-Transport-Security header (only once HTTPS works everywhere).', 'index-sentinel' ) );

		$uploads = wp_get_upload_dir();
		$ht      = is_readable( $uploads['basedir'] . '/.htaccess' ) ? (string) file_get_contents( $uploads['basedir'] . '/.htaccess' ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$server  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
		$apache  = (bool) preg_match( '/apache|litespeed/i', $server );
		$add( 'uploads_php', __( 'PHP blocked in the uploads folder', 'index-sentinel' ), $apache ? (bool) preg_match( '/php/i', $ht ) : null, __( 'A file uploaded by an attacker cannot run.', 'index-sentinel' ), __( 'Add a rule that denies *.php in wp-content/uploads/.htaccess (Apache/LiteSpeed) or in your Nginx config.', 'index-sentinel' ) );
		$add( 'indexable', __( 'Search engines allowed', 'index-sentinel' ), '1' === (string) get_option( 'blog_public' ), __( 'The site must be visible in Google.', 'index-sentinel' ), __( 'Untick "Discourage search engines" in Settings > Reading.', 'index-sentinel' ) );
		$add( 'alerts', __( 'Email alerts enabled', 'index-sentinel' ), (bool) Settings::get( 'alerts' ), __( 'You hear about problems the day they happen.', 'index-sentinel' ), __( 'Turn on alerts in Settings.', 'index-sentinel' ) );

		/**
		 * Filter the security checklist (add-ons can add their own checks).
		 *
		 * @param array[] $c Checks.
		 */
		return (array) apply_filters( 'index_sentinel_hardening_checks', $c );
	}
}
