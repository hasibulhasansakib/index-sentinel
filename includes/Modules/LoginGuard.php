<?php
/**
 * Brute-force protection and admin account monitoring.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Alerts;
use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * - Too many failed logins from one IP within 15 minutes locks that IP out.
 * - Every login, good or bad, is logged.
 * - A new administrator, or a user promoted to administrator, triggers an immediate alert.
 */
final class LoginGuard {

	/**
	 * Hooks.
	 */
	public function init() {
		// Priority 99: after core's own checks, which would otherwise overwrite the lockout error.
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 99, 1 );
		add_action( 'wp_login_failed', array( $this, 'failed' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'success' ), 10, 1 );
		add_action( 'user_register', array( $this, 'new_user' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'role_changed' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'role_added' ), 10, 2 );
	}

	/**
	 * Transient key for an IP.
	 *
	 * @param string $ip IP.
	 * @return string
	 */
	private function key( $ip ) {
		return 'index_sentinel_lock_' . md5( $ip );
	}

	/**
	 * Refuse logins from a locked-out IP.
	 *
	 * @param \WP_User|\WP_Error|null $user Result so far.
	 * @return \WP_User|\WP_Error|null
	 */
	public function check_lockout( $user ) {
		$until = (int) get_transient( $this->key( Store::ip() ) );
		if ( $until > time() ) {
			$mins = max( 1, (int) ceil( ( $until - time() ) / 60 ) );
			/* translators: %d: minutes until the lockout ends. */
			return new \WP_Error( 'index_sentinel_locked', sprintf( _n( 'Too many failed login attempts. Try again in %d minute.', 'Too many failed login attempts. Try again in %d minutes.', $mins, 'index-sentinel' ), $mins ) );
		}
		return $user;
	}

	/**
	 * Count a failure and lock out when the limit is reached.
	 *
	 * @param string $username Attempted username.
	 */
	public function failed( $username ) {
		$ip = Store::ip();
		Store::log( 'login_fail', __( 'Failed login', 'index-sentinel' ), 'notice', array( 'user' => sanitize_user( (string) $username ) ), $ip );
		if ( ! $ip || get_transient( $this->key( $ip ) ) ) {
			return;
		}
		$recent = Store::count( 'login_fail', gmdate( 'Y-m-d H:i:s', time() - 15 * MINUTE_IN_SECONDS ), $ip );
		if ( $recent >= (int) Settings::get( 'max_attempts' ) ) {
			$minutes = (int) Settings::get( 'lockout_minutes' );
			set_transient( $this->key( $ip ), time() + $minutes * 60, $minutes * 60 );
			/* translators: 1: minutes, 2: number of failed attempts. */
			Store::log( 'lockout', sprintf( __( 'IP locked out for %1$d minutes after %2$d failed logins', 'index-sentinel' ), $minutes, $recent ), 'warning', array( 'user' => sanitize_user( (string) $username ) ), $ip );
		}
	}

	/**
	 * Log a successful login.
	 *
	 * @param string $login Username.
	 */
	public function success( $login ) {
		Store::log( 'login_ok', __( 'Successful login', 'index-sentinel' ), 'info', array( 'user' => $login ) );
	}

	/**
	 * New user registered.
	 *
	 * @param int $user_id User ID.
	 */
	public function new_user( $user_id ) {
		$user = get_userdata( $user_id );
		if ( $user && in_array( 'administrator', (array) $user->roles, true ) ) {
			$this->admin_alert( $user, __( 'New administrator account created', 'index-sentinel' ) );
		}
	}

	/**
	 * Role set.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Previous roles.
	 */
	public function role_changed( $user_id, $role, $old_roles ) {
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
			$this->admin_alert( get_userdata( $user_id ), __( 'User promoted to administrator', 'index-sentinel' ) );
		}
	}

	/**
	 * Role added.
	 *
	 * @param int    $user_id User ID.
	 * @param string $role    Role.
	 */
	public function role_added( $user_id, $role ) {
		if ( 'administrator' === $role ) {
			$this->admin_alert( get_userdata( $user_id ), __( 'Administrator role added to a user', 'index-sentinel' ) );
		}
	}

	/**
	 * Log and email an admin-account change.
	 *
	 * @param \WP_User|false $user User.
	 * @param string         $what What happened.
	 */
	private function admin_alert( $user, $what ) {
		if ( ! $user ) {
			return;
		}
		/* translators: 1: what happened, 2: username, 3: email. */
		$detail = sprintf( __( '%1$s: %2$s (%3$s). If this was not you, remove the account and change all passwords.', 'index-sentinel' ), $what, $user->user_login, $user->user_email );
		Store::log( 'admin_change', $detail, 'critical', array( 'user_id' => $user->ID ) );
		( new Alerts() )->send_now( $what, array( $detail ) );
	}
}
