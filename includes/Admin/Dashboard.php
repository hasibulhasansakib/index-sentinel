<?php
/**
 * Admin screen.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Admin;

use IndexSentinel\Alerts;
use IndexSentinel\Modules\Google;
use IndexSentinel\Modules\Hardening;
use IndexSentinel\Modules\LogReader;
use IndexSentinel\Modules\Scanner;
use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * "Index Sentinel" admin page: an overview with a score, then one tab per area.
 * Long jobs run over AJAX so the page never times out.
 */
final class Dashboard {

	const SLUG = 'index-sentinel';

	/**
	 * Hooks.
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'wp_ajax_index_sentinel_run', array( $this, 'ajax_run' ) );
		add_action( 'admin_post_index_sentinel_action', array( $this, 'post_action' ) );
		add_action( 'wp_dashboard_setup', array( $this, 'widget' ) );
	}

	/**
	 * Tabs. Add-ons can add tabs with the `index_sentinel_tabs` filter and render them on
	 * the `index_sentinel_render_tab_{id}` action.
	 *
	 * @return array id => label
	 */
	private function tabs() {
		$tabs = array(
			'overview'  => __( 'Overview', 'index-sentinel' ),
			'scan'      => __( 'Malware Scan', 'index-sentinel' ),
			'google'    => __( 'Google Index', 'index-sentinel' ),
			'traffic'   => __( 'Traffic & Spam', 'index-sentinel' ),
			'activity'  => __( 'Activity', 'index-sentinel' ),
			'hardening' => __( 'Hardening', 'index-sentinel' ),
			'settings'  => __( 'Settings', 'index-sentinel' ),
		);
		return (array) apply_filters( 'index_sentinel_tabs', $tabs );
	}

	/**
	 * Admin menu.
	 */
	public function menu() {
		$score = $this->score();
		$badge = $score['critical'] ? ' <span class="awaiting-mod">' . (int) $score['critical'] . '</span>' : '';
		add_menu_page(
			__( 'Index Sentinel', 'index-sentinel' ),
			__( 'Index Sentinel', 'index-sentinel' ) . $badge,
			'manage_options',
			self::SLUG,
			array( $this, 'render' ),
			'dashicons-shield-alt',
			80
		);
	}

	/**
	 * Styles and scripts on our screen and the WP dashboard (widget).
	 *
	 * @param string $hook Screen hook.
	 */
	public function assets( $hook ) {
		if ( 'toplevel_page_' . self::SLUG !== $hook && 'index.php' !== $hook ) {
			return;
		}
		wp_enqueue_style( 'index-sentinel-admin', INDEX_SENTINEL_URL . 'assets/admin.css', array(), INDEX_SENTINEL_VERSION );
		wp_enqueue_script( 'index-sentinel-admin', INDEX_SENTINEL_URL . 'assets/admin.js', array(), INDEX_SENTINEL_VERSION, true );
		wp_localize_script(
			'index-sentinel-admin',
			'IndexSentinel',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'index_sentinel_run' ),
				'i18n'  => array(
					'scanning' => __( 'Scanning every file. This can take a minute…', 'index-sentinel' ),
					'working'  => __( 'Working…', 'index-sentinel' ),
					'failed'   => __( 'The request failed or timed out. The job may still finish; reload in a minute.', 'index-sentinel' ),
					'done'     => __( 'Done', 'index-sentinel' ),
				),
			)
		);
	}

	/* ---------------------------------------------------------------- actions */

	/**
	 * AJAX: run a long job.
	 */
	public function ajax_run() {
		check_ajax_referer( 'index_sentinel_run', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'You are not allowed to do this.', 'index-sentinel' ), 403 );
		}
		$task = isset( $_POST['task'] ) ? sanitize_key( wp_unslash( $_POST['task'] ) ) : '';
		switch ( $task ) {
			case 'scan':
				$r = ( new Scanner() )->run();
				/* translators: 1: files checked, 2: findings. */
				wp_send_json_success( sprintf( __( 'Scan done: %1$d files checked, %2$d findings.', 'index-sentinel' ), $r['files'], count( $r['findings'] ) ) );
				break;
			case 'google':
				$r = ( new Google() )->refresh( 8 ); // Quick: the daily job inspects every URL.
				if ( isset( $r['error'] ) ) {
					wp_send_json_error( $r['error'] );
				}
				wp_send_json_success( __( 'Google data refreshed.', 'index-sentinel' ) );
				break;
			case 'traffic':
				$r = ( new LogReader() )->run();
				if ( isset( $r['error'] ) ) {
					wp_send_json_error( $r['error'] );
				}
				wp_send_json_success( __( 'Access logs read.', 'index-sentinel' ) );
				break;
			case 'cloak':
				Store::set( 'cloak', ( new Scanner() )->cloaking_check() );
				wp_send_json_success( __( 'Googlebot check done.', 'index-sentinel' ) );
				break;
			case 'hardening':
				delete_transient( 'index_sentinel_hardening' );
				wp_send_json_success( __( 'Checklist refreshed.', 'index-sentinel' ) );
				break;
		}
		wp_send_json_error( __( 'Unknown task.', 'index-sentinel' ) );
	}

	/**
	 * Form posts: settings, quarantine, restore, baseline, test email.
	 */
	public function post_action() {
		check_admin_referer( 'index_sentinel_action' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'index-sentinel' ) );
		}
		$do  = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		$tab = 'overview';
		$msg = '';
		switch ( $do ) {
			case 'accept_baseline':
				Scanner::accept_baseline();
				$tab = 'scan';
				$msg = __( 'Current files marked as trusted. Run a new scan to clear the notices.', 'index-sentinel' );
				break;
			case 'quarantine':
				$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
				$tab  = 'scan';
				$msg  = Scanner::quarantine( $path ) ? __( 'File moved to quarantine.', 'index-sentinel' ) : __( 'Could not quarantine that file.', 'index-sentinel' );
				break;
			case 'restore':
				$dest = isset( $_POST['dest'] ) ? sanitize_text_field( wp_unslash( $_POST['dest'] ) ) : '';
				$tab  = 'scan';
				$msg  = Scanner::restore( $dest ) ? __( 'File restored.', 'index-sentinel' ) : __( 'Could not restore that file.', 'index-sentinel' );
				break;
			case 'settings':
				$input = isset( $_POST['index_sentinel'] ) && is_array( $_POST['index_sentinel'] ) ? wp_unslash( $_POST['index_sentinel'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitised field by field in Settings::save().
				Settings::save( $input );
				delete_transient( 'index_sentinel_hardening' );
				$tab = 'settings';
				$msg = __( 'Settings saved.', 'index-sentinel' );
				break;
			case 'add_preset':
				$input                  = Settings::all();
				$input['spam_patterns'] = trim( $input['spam_patterns'] . "\n" . Settings::JAPANESE_HACK_PATTERN );
				Settings::save( $input );
				$tab = 'settings';
				$msg = __( 'Japanese keyword hack pattern added.', 'index-sentinel' );
				break;
			case 'test_email':
				( new Alerts() )->send_now( __( 'Test alert', 'index-sentinel' ), array( __( 'This is a test from Index Sentinel. Alerts are working.', 'index-sentinel' ) ) );
				$tab = 'settings';
				/* translators: %s: email address. */
				$msg = sprintf( __( 'Test email sent to %s.', 'index-sentinel' ), Settings::get( 'alert_email' ) );
				break;
		}
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                => self::SLUG,
					'tab'                 => $tab,
					'index_sentinel_msg'  => rawurlencode( $msg ),
					'_wpnonce'            => wp_create_nonce( 'index_sentinel_msg' ),
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * A one-button form that posts an action.
	 *
	 * @param string $do      Action.
	 * @param string $label   Button label.
	 * @param string $class   Button class.
	 * @param array  $fields  Hidden fields.
	 * @param string $confirm Confirmation text.
	 * @return string
	 */
	private function form( $do, $label, $class = 'idxs-btn', $fields = array(), $confirm = '' ) {
		$h  = '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="idxs-inline"' . ( $confirm ? ' data-idxs-confirm="' . esc_attr( $confirm ) . '"' : '' ) . '>';
		$h .= wp_nonce_field( 'index_sentinel_action', '_wpnonce', true, false );
		$h .= '<input type="hidden" name="action" value="index_sentinel_action"><input type="hidden" name="do" value="' . esc_attr( $do ) . '">';
		foreach ( $fields as $k => $v ) {
			$h .= '<input type="hidden" name="' . esc_attr( $k ) . '" value="' . esc_attr( $v ) . '">';
		}
		return $h . '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/**
	 * A button that runs an AJAX job.
	 *
	 * @param string $task  Task.
	 * @param string $label Label.
	 * @param string $class Class.
	 * @return string
	 */
	private function run_button( $task, $label, $class = 'idxs-btn idxs-btn--primary' ) {
		return '<button type="button" class="' . esc_attr( $class ) . '" data-idxs-run="' . esc_attr( $task ) . '">' . esc_html( $label ) . '</button>';
	}

	/* ---------------------------------------------------------------- data */

	/**
	 * Cached security checklist.
	 *
	 * @return array
	 */
	private function hardening() {
		$c = get_transient( 'index_sentinel_hardening' );
		if ( false === $c ) {
			$c = ( new Hardening() )->checks();
			set_transient( 'index_sentinel_hardening', $c, HOUR_IN_SECONDS );
		}
		return (array) $c;
	}

	/**
	 * Score 0-100 plus counts.
	 *
	 * @return array
	 */
	public function score() {
		$scan     = Store::get( 'scan', array() );
		$counts   = isset( $scan['counts'] ) ? $scan['counts'] : array();
		$critical = isset( $counts['critical'] ) ? (int) $counts['critical'] : 0;
		$warning  = isset( $counts['warning'] ) ? (int) $counts['warning'] : 0;
		$cloak    = Store::get( 'cloak', array() );
		$cloak_n  = ! empty( $cloak['problems'] ) ? count( $cloak['problems'] ) : 0;
		$google   = Store::get( 'google', array() );
		$unknown  = 0;
		foreach ( isset( $google['analytics']['unknown'] ) ? $google['analytics']['unknown'] : array() as $u ) {
			$unknown += ( $u['impressions'] >= 3 ) ? 1 : 0;
		}
		$hard   = get_transient( 'index_sentinel_hardening' );
		$failed = 0;
		foreach ( is_array( $hard ) ? $hard : array() as $c ) {
			$failed += ( false === $c['ok'] ) ? 1 : 0;
		}
		$score = 100 - min( 60, $critical * 20 ) - min( 15, $warning * 3 ) - min( 15, $failed * 3 ) - ( $unknown ? 10 : 0 ) - ( $cloak_n ? 30 : 0 );
		if ( ! $scan ) {
			$score = min( $score, 70 );
		}
		$result = array(
			'score'    => max( 0, $score ),
			'critical' => $critical + $cloak_n,
			'warning'  => $warning,
			'failed'   => $failed,
			'unknown'  => $unknown,
			'scanned'  => (bool) $scan,
		);
		/**
		 * Filter the security score shown on the dashboard.
		 *
		 * @param array $result Score and counts.
		 */
		return (array) apply_filters( 'index_sentinel_score', $result );
	}

	/* ---------------------------------------------------------------- render helpers */

	/**
	 * "x ago".
	 *
	 * @param int $ts Timestamp.
	 * @return string
	 */
	private function ago( $ts ) {
		/* translators: %s: human time difference, e.g. "5 mins". */
		return $ts ? sprintf( __( '%s ago', 'index-sentinel' ), human_time_diff( (int) $ts ) ) : __( 'never', 'index-sentinel' );
	}

	/**
	 * Status pill.
	 *
	 * @param string $text Text.
	 * @param string $tone good|warn|bad|muted.
	 * @return string
	 */
	private function pill( $text, $tone ) {
		return '<span class="idxs-pill idxs-pill--' . esc_attr( $tone ) . '">' . esc_html( $text ) . '</span>';
	}

	/**
	 * Open a card.
	 *
	 * @param string $title Title.
	 * @param string $icon  Dashicon name.
	 * @param string $extra Extra header HTML (already escaped).
	 */
	private function card_open( $title, $icon, $extra = '' ) {
		echo '<section class="idxs-card"><div class="idxs-card__head"><h2><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span>' . esc_html( $title ) . '</h2>' . $extra . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $extra is built from escaped parts.
	}

	/**
	 * Inline SVG bar chart.
	 *
	 * @param array  $series Label => value.
	 * @param string $tone   blue|green|red.
	 * @return string
	 */
	private function bars( $series, $tone = 'blue' ) {
		if ( ! $series ) {
			return '<p class="idxs-muted">' . esc_html__( 'No data yet.', 'index-sentinel' ) . '</p>';
		}
		$h   = 90;
		$max = max( 1, max( $series ) );
		$w   = 100 / max( count( $series ), 14 );
		$out = '<svg class="idxs-bars idxs-bars--' . esc_attr( $tone ) . '" viewBox="0 0 100 ' . $h . '" preserveAspectRatio="none" role="img" aria-label="' . esc_attr__( 'Chart', 'index-sentinel' ) . '">';
		$i   = 0;
		foreach ( $series as $label => $v ) {
			$bh   = $v ? max( 1.5, $v / $max * ( $h - 4 ) ) : 0;
			$out .= '<rect x="' . esc_attr( round( $i * $w + $w * 0.15, 2 ) ) . '" y="' . esc_attr( round( $h - $bh, 2 ) ) . '" width="' . esc_attr( round( $w * 0.7, 2 ) ) . '" height="' . esc_attr( round( $bh, 2 ) ) . '"><title>' . esc_html( $label . ': ' . number_format_i18n( $v ) ) . '</title></rect>';
			$i++;
		}
		$keys = array_keys( $series );
		return $out . '</svg><div class="idxs-bars__axis"><span>' . esc_html( reset( $keys ) ) . '</span><span>' . esc_html( end( $keys ) ) . '</span></div>';
	}

	/**
	 * Simple two-column table from label => number.
	 *
	 * @param array $rows Rows.
	 * @param bool  $code Show label as code.
	 */
	private function kv_table( $rows, $code = true ) {
		if ( ! $rows ) {
			echo '<p class="idxs-muted">' . esc_html__( 'Nothing to show.', 'index-sentinel' ) . '</p>';
			return;
		}
		echo '<table class="idxs-table"><tbody>';
		foreach ( $rows as $k => $n ) {
			echo '<tr><td>' . ( $code ? '<code>' . esc_html( $k ) . '</code>' : esc_html( $k ) ) . '</td><td class="num">' . esc_html( number_format_i18n( $n ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	/* ---------------------------------------------------------------- render */

	/**
	 * Page.
	 */
	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$tabs = $this->tabs();
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation only.
		$tab  = isset( $tabs[ $tab ] ) ? $tab : 'overview';
		$msg  = '';
		if ( isset( $_GET['index_sentinel_msg'], $_GET['_wpnonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'index_sentinel_msg' ) ) {
			$msg = sanitize_text_field( rawurldecode( wp_unslash( $_GET['index_sentinel_msg'] ) ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		echo '<div class="wrap idxs">';
		echo '<header class="idxs-top"><div><h1><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>' . esc_html__( 'Index Sentinel', 'index-sentinel' ) . '</h1>';
		/* translators: %s: site domain. */
		echo '<p>' . esc_html( sprintf( __( 'SEO spam, malware and Google index health for %s', 'index-sentinel' ), wp_parse_url( home_url(), PHP_URL_HOST ) ) ) . '</p></div>';
		echo '<div class="idxs-top__actions">' . $this->run_button( 'scan', __( 'Run full scan', 'index-sentinel' ) ) . '</div></header>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<div class="idxs-toast" id="idxs-toast" role="status" aria-live="polite" hidden></div>';
		if ( $msg ) {
			echo '<div class="idxs-note idxs-note--ok">' . esc_html( $msg ) . '</div>';
		}
		echo '<nav class="idxs-tabs" aria-label="' . esc_attr__( 'Index Sentinel sections', 'index-sentinel' ) . '">';
		foreach ( $tabs as $id => $label ) {
			echo '<a class="' . ( $id === $tab ? 'is-active' : '' ) . '" href="' . esc_url( add_query_arg( array( 'page' => self::SLUG, 'tab' => $id ), admin_url( 'admin.php' ) ) ) . '">' . esc_html( $label ) . '</a>';
		}
		echo '</nav><main class="idxs-main">';
		if ( method_exists( $this, 'tab_' . $tab ) ) {
			$this->{'tab_' . $tab}();
		} else {
			/**
			 * Render an add-on tab.
			 */
			do_action( 'index_sentinel_render_tab_' . $tab );
		}
		echo '</main><footer class="idxs-foot">';
		/* translators: 1: version, 2: author link. */
		printf( esc_html__( 'Index Sentinel %1$s by %2$s', 'index-sentinel' ), esc_html( INDEX_SENTINEL_VERSION ), '<a href="https://hasibulhasansakib.com/" target="_blank" rel="noopener">Hasibul Hasan Sakib</a>' );
		echo '</footer></div>';
	}

	/**
	 * Overview tab.
	 */
	private function tab_overview() {
		$this->hardening();
		$s       = $this->score();
		$scan    = Store::get( 'scan', array() );
		$cloak   = Store::get( 'cloak', array() );
		$google  = Store::get( 'google', array() );
		$traffic = Store::get( 'traffic', array() );
		$tone    = $s['score'] >= 85 ? 'good' : ( $s['score'] >= 60 ? 'warn' : 'bad' );
		$labels  = array(
			'good' => __( 'Protected', 'index-sentinel' ),
			'warn' => __( 'Needs attention', 'index-sentinel' ),
			'bad'  => __( 'At risk', 'index-sentinel' ),
		);
		if ( ! $s['scanned'] ) {
			$labels[ $tone ] = __( 'Run your first scan', 'index-sentinel' );
		}

		if ( ! $scan ) {
			$this->card_open( __( 'Getting started', 'index-sentinel' ), 'flag' );
			echo '<ol class="idxs-steps">';
			echo '<li>' . esc_html__( 'Run your first full scan (button above). It sets the trusted baseline of your files.', 'index-sentinel' ) . '</li>';
			echo '<li>' . esc_html__( 'If your site was hit by an SEO spam hack, add its spam URL pattern in Settings so Index Sentinel can track the clean-up.', 'index-sentinel' ) . '</li>';
			echo '<li>' . esc_html__( 'Optional: install Site Kit by Google and connect Search Console to see which of your pages Google has indexed.', 'index-sentinel' ) . '</li>';
			echo '<li>' . esc_html__( 'Send a test alert email from Settings. After that, everything runs automatically every day.', 'index-sentinel' ) . '</li>';
			echo '</ol></section>';
		}

		echo '<div class="idxs-hero idxs-hero--' . esc_attr( $tone ) . '">';
		echo '<svg class="idxs-ring" viewBox="0 0 110 110" aria-hidden="true"><circle cx="55" cy="55" r="46" class="idxs-ring__bg"/><circle cx="55" cy="55" r="46" class="idxs-ring__fg" stroke-dasharray="' . esc_attr( round( $s['score'] / 100 * 289, 1 ) ) . ' 289"/><text x="55" y="64" text-anchor="middle">' . esc_html( $s['score'] ) . '</text></svg>';
		echo '<div><h2>' . esc_html( $labels[ $tone ] ) . '</h2><ul class="idxs-hero__list">';
		/* translators: %d: number of critical issues. */
		echo '<li>' . ( $s['critical'] ? $this->pill( sprintf( _n( '%d critical issue', '%d critical issues', $s['critical'], 'index-sentinel' ), $s['critical'] ), 'bad' ) : $this->pill( __( 'No critical issues', 'index-sentinel' ), 'good' ) ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		/* translators: %d: number of unknown URLs. */
		echo '<li>' . ( $s['unknown'] ? $this->pill( sprintf( _n( '%d unknown URL in Google', '%d unknown URLs in Google', $s['unknown'], 'index-sentinel' ), $s['unknown'] ), 'bad' ) : $this->pill( __( 'No unknown URLs in Google', 'index-sentinel' ), 'good' ) ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		/* translators: %d: number of open hardening items. */
		echo '<li>' . ( $s['failed'] ? $this->pill( sprintf( _n( '%d hardening item open', '%d hardening items open', $s['failed'], 'index-sentinel' ), $s['failed'] ), 'warn' ) : $this->pill( __( 'Hardening complete', 'index-sentinel' ), 'good' ) ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		/* translators: %s: time ago. */
		echo '</ul><p class="idxs-muted">' . esc_html( sprintf( __( 'Last full scan: %s. A full check runs every day and a Googlebot check every hour.', 'index-sentinel' ), $this->ago( isset( $scan['time'] ) ? $scan['time'] : 0 ) ) ) . '</p></div></div>';

		echo '<div class="idxs-grid">';

		$this->card_open( __( 'Malware & files', 'index-sentinel' ), 'search', $this->run_button( 'scan', __( 'Scan now', 'index-sentinel' ), 'idxs-btn' ) );
		if ( $scan ) {
			$c = isset( $scan['counts'] ) ? $scan['counts'] : array();
			echo '<div class="idxs-stats">';
			echo '<div><b class="' . ( empty( $c['critical'] ) ? 'is-good' : 'is-bad' ) . '">' . esc_html( isset( $c['critical'] ) ? $c['critical'] : 0 ) . '</b><span>' . esc_html__( 'Critical', 'index-sentinel' ) . '</span></div>';
			echo '<div><b>' . esc_html( isset( $c['warning'] ) ? $c['warning'] : 0 ) . '</b><span>' . esc_html__( 'Warnings', 'index-sentinel' ) . '</span></div>';
			echo '<div><b>' . esc_html( number_format_i18n( $scan['files'] ) ) . '</b><span>' . esc_html__( 'Files checked', 'index-sentinel' ) . '</span></div></div>';
		} else {
			echo '<p class="idxs-muted">' . esc_html__( 'No scan yet. Click "Scan now".', 'index-sentinel' ) . '</p>';
		}
		echo '</section>';

		$this->card_open( __( 'What Google sees', 'index-sentinel' ), 'visibility', $this->run_button( 'cloak', __( 'Check now', 'index-sentinel' ), 'idxs-btn' ) );
		if ( ! $cloak ) {
			echo '<p class="idxs-muted">' . esc_html__( 'Not checked yet.', 'index-sentinel' ) . '</p>';
		} elseif ( empty( $cloak['problems'] ) ) {
			echo '<p class="idxs-big is-good">' . esc_html__( 'Clean', 'index-sentinel' ) . '</p>';
			/* translators: %s: time ago. */
			echo '<p class="idxs-muted">' . esc_html( sprintf( __( 'The homepage served to Googlebot has no spam text and no hidden links. Checked %s.', 'index-sentinel' ), $this->ago( $cloak['time'] ) ) ) . '</p>';
		} else {
			echo '<p class="idxs-big is-bad">' . esc_html__( 'Problem found', 'index-sentinel' ) . '</p><ul class="idxs-list">';
			foreach ( $cloak['problems'] as $p ) {
				echo '<li>' . esc_html( $p ) . '</li>';
			}
			echo '</ul>';
		}
		echo '</section>';

		$this->card_open( __( 'Google index', 'index-sentinel' ), 'google', Google::available() ? $this->run_button( 'google', __( 'Refresh', 'index-sentinel' ), 'idxs-btn' ) : '' );
		if ( ! empty( $google['urls'] ) ) {
			$indexed = 0;
			foreach ( $google['urls'] as $u ) {
				$indexed += ( 'PASS' === $u['verdict'] ) ? 1 : 0;
			}
			$total = count( $google['urls'] );
			$spamn = isset( $google['analytics']['spam_count'] ) ? (int) $google['analytics']['spam_count'] : 0;
			echo '<div class="idxs-stats">';
			echo '<div><b class="is-good">' . esc_html( $indexed . '/' . $total ) . '</b><span>' . esc_html__( 'Your pages indexed', 'index-sentinel' ) . '</span></div>';
			echo '<div><b class="' . ( $spamn ? 'is-warn' : 'is-good' ) . '">' . esc_html( $spamn ) . '</b><span>' . esc_html__( 'Known spam pages still shown', 'index-sentinel' ) . '</span></div>';
			echo '<div><b class="' . ( $s['unknown'] ? 'is-bad' : 'is-good' ) . '">' . esc_html( $s['unknown'] ) . '</b><span>' . esc_html__( 'Unknown URLs', 'index-sentinel' ) . '</span></div></div>';
			echo '<div class="idxs-progress"><span style="width:' . esc_attr( $total ? round( $indexed / $total * 100 ) : 0 ) . '%"></span></div>';
		} elseif ( ! Google::available() ) {
			echo '<p class="idxs-muted">' . esc_html__( 'Optional. Install Site Kit by Google and connect Search Console to see your index status here.', 'index-sentinel' ) . '</p>';
		} else {
			echo '<p class="idxs-muted">' . esc_html( isset( $google['error'] ) ? $google['error'] : __( 'Not loaded yet. Click Refresh.', 'index-sentinel' ) ) . '</p>';
		}
		echo '</section>';

		$days = isset( $traffic['days'] ) ? $traffic['days'] : array();
		$this->card_open( __( 'Spam clean-up progress', 'index-sentinel' ), 'chart-bar', $this->run_button( 'traffic', __( 'Refresh', 'index-sentinel' ), 'idxs-btn' ) );
		if ( $days && Settings::spam_patterns() ) {
			$gone = array_sum( wp_list_pluck( $days, 'google_gone' ) );
			/* translators: %s: number of URLs. */
			echo '<p><b class="idxs-big">' . esc_html( number_format_i18n( $gone ) ) . '</b> ' . esc_html__( 'spam URLs re-checked by Googlebot in 30 days and found gone (410/404), so Google drops them.', 'index-sentinel' ) . '</p>';
			echo $this->bars( wp_list_pluck( $days, 'google_gone' ), 'green' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		} elseif ( ! Settings::spam_patterns() ) {
			echo '<p class="idxs-muted">' . esc_html__( 'Add the spam URL pattern of a past hack in Settings to track how fast Google forgets it.', 'index-sentinel' ) . '</p>';
		} else {
			echo '<p class="idxs-muted">' . esc_html( isset( $traffic['error'] ) ? $traffic['error'] : __( 'Logs not read yet. Click Refresh.', 'index-sentinel' ) ) . '</p>';
		}
		echo '</section>';

		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-7 days' ) );
		$last  = Store::events( array( 'login_ok' ), 1 );
		$this->card_open( __( 'Logins (7 days)', 'index-sentinel' ), 'admin-users' );
		echo '<div class="idxs-stats">';
		echo '<div><b>' . esc_html( Store::count( 'login_fail', $since ) ) . '</b><span>' . esc_html__( 'Failed logins', 'index-sentinel' ) . '</span></div>';
		echo '<div><b>' . esc_html( Store::count( 'lockout', $since ) ) . '</b><span>' . esc_html__( 'IPs locked out', 'index-sentinel' ) . '</span></div>';
		echo '<div><b>' . esc_html( Store::count( 'blocked', $since ) ) . '</b><span>' . esc_html__( 'Probes blocked', 'index-sentinel' ) . '</span></div></div>';
		if ( $last ) {
			$ctx = json_decode( (string) $last[0]['context'], true );
			/* translators: 1: username, 2: IP, 3: time ago. */
			echo '<p class="idxs-muted">' . esc_html( sprintf( __( 'Last login: %1$s from %2$s, %3$s.', 'index-sentinel' ), isset( $ctx['user'] ) ? $ctx['user'] : '', $last[0]['ip'], $this->ago( strtotime( $last[0]['created_at'] . ' UTC' ) ) ) ) . '</p>';
		}
		echo '</section>';

		$hard = $this->hardening();
		$ok   = 0;
		$all  = 0;
		foreach ( $hard as $c ) {
			if ( null !== $c['ok'] ) {
				$all++;
				$ok += $c['ok'] ? 1 : 0;
			}
		}
		$this->card_open( __( 'Hardening', 'index-sentinel' ), 'lock' );
		/* translators: 1: passed checks, 2: total checks. */
		echo '<p><b class="idxs-big ' . ( $ok === $all ? 'is-good' : 'is-warn' ) . '">' . esc_html( $ok . '/' . $all ) . '</b> ' . esc_html__( 'checks passed', 'index-sentinel' ) . '</p>';
		echo '<div class="idxs-progress"><span style="width:' . esc_attr( $all ? round( $ok / $all * 100 ) : 0 ) . '%"></span></div>';
		echo '</section></div>';
	}

	/**
	 * Malware scan tab.
	 */
	private function tab_scan() {
		$scan = Store::get( 'scan', array() );
		$this->card_open( __( 'Malware & integrity scan', 'index-sentinel' ), 'search', $this->run_button( 'scan', __( 'Run full scan', 'index-sentinel' ) ) );
		echo '<p class="idxs-muted">' . esc_html__( 'Checks WordPress core and WordPress.org plugins against official checksums, your own plugins and themes against a trusted baseline, every other PHP file against malware patterns, media files hiding PHP, the database and what Googlebot sees.', 'index-sentinel' ) . '</p>';
		if ( ! $scan ) {
			echo '<p>' . esc_html__( 'No scan yet.', 'index-sentinel' ) . '</p></section>';
			return;
		}
		/* translators: 1: time ago, 2: files, 3: seconds. */
		echo '<p>' . esc_html( sprintf( __( 'Last scan %1$s · %2$s files · %3$s s', 'index-sentinel' ), $this->ago( $scan['time'] ), number_format_i18n( $scan['files'] ), $scan['duration'] ) ) . '</p>';
		if ( empty( $scan['findings'] ) ) {
			echo '<div class="idxs-empty"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><p>' . esc_html__( 'Nothing suspicious found.', 'index-sentinel' ) . '</p></div>';
		} else {
			$order    = array( 'critical' => 0, 'warning' => 1, 'notice' => 2 );
			$findings = $scan['findings'];
			usort(
				$findings,
				static function ( $a, $b ) use ( $order ) {
					return ( isset( $order[ $a['severity'] ] ) ? $order[ $a['severity'] ] : 3 ) <=> ( isset( $order[ $b['severity'] ] ) ? $order[ $b['severity'] ] : 3 );
				}
			);
			$tones = array( 'critical' => 'bad', 'warning' => 'warn' );
			echo '<table class="idxs-table"><thead><tr><th>' . esc_html__( 'Severity', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Where', 'index-sentinel' ) . '</th><th>' . esc_html__( 'What', 'index-sentinel' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $findings as $f ) {
				$can    = is_file( ABSPATH . $f['path'] ) && in_array( $f['severity'], array( 'critical', 'warning' ), true );
				$action = $can ? $this->form( 'quarantine', __( 'Quarantine', 'index-sentinel' ), 'idxs-btn idxs-btn--danger idxs-btn--sm', array( 'path' => $f['path'] ), __( 'Move this file to quarantine? You can restore it later.', 'index-sentinel' ) ) : '';
				echo '<tr><td>' . $this->pill( ucfirst( $f['severity'] ), isset( $tones[ $f['severity'] ] ) ? $tones[ $f['severity'] ] : 'muted' ) . '</td><td><code>' . esc_html( $f['path'] ) . '</code></td><td>' . esc_html( $f['detail'] ) . '</td><td>' . $action . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '</tbody></table>';
			$changed = 0;
			foreach ( $scan['findings'] as $f ) {
				$changed += in_array( $f['type'], array( 'file-new', 'file-changed' ), true ) ? 1 : 0;
			}
			if ( $changed ) {
				/* translators: %d: number of files. */
				echo '<div class="idxs-note">' . esc_html( sprintf( _n( '%d file in your plugins or themes changed since you last marked files as trusted. If you made the change (for example an update), accept it:', '%d files in your plugins or themes changed since you last marked files as trusted. If you made the change (for example an update), accept them:', $changed, 'index-sentinel' ), $changed ) ) . ' ' . $this->form( 'accept_baseline', __( 'Mark current files as trusted', 'index-sentinel' ), 'idxs-btn idxs-btn--sm' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
		}
		echo '</section>';

		$q = Store::get( 'quarantine', array() );
		if ( $q ) {
			$this->card_open( __( 'Quarantine', 'index-sentinel' ), 'archive' );
			echo '<table class="idxs-table"><thead><tr><th>' . esc_html__( 'Original file', 'index-sentinel' ) . '</th><th>' . esc_html__( 'When', 'index-sentinel' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $q as $dest => $item ) {
				echo '<tr><td><code>' . esc_html( $item['from'] ) . '</code></td><td>' . esc_html( $this->ago( $item['time'] ) ) . '</td><td>' . $this->form( 'restore', __( 'Restore', 'index-sentinel' ), 'idxs-btn idxs-btn--sm', array( 'dest' => $dest ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '</tbody></table></section>';
		}
	}

	/**
	 * Google tab.
	 */
	private function tab_google() {
		$g = Store::get( 'google', array() );
		$this->card_open( __( 'Google Search Console', 'index-sentinel' ), 'google', Google::available() ? $this->run_button( 'google', __( 'Refresh from Google', 'index-sentinel' ) ) : '' );
		if ( ! Google::available() ) {
			echo '<div class="idxs-note">' . esc_html__( 'This part is optional. Install "Site Kit by Google", connect it to Search Console, and Index Sentinel will use that connection. No extra login or API key is needed.', 'index-sentinel' ) . '</div></section>';
			return;
		}
		if ( ! empty( $g['error'] ) ) {
			echo '<div class="idxs-note idxs-note--bad">' . esc_html( $g['error'] ) . '</div>';
		}
		/* translators: %s: time ago. */
		echo '<p class="idxs-muted">' . esc_html( sprintf( __( 'Updated %s. Page checks rotate daily, so every page is re-checked every few days.', 'index-sentinel' ), $this->ago( isset( $g['updated'] ) ? $g['updated'] : 0 ) ) ) . '</p>';
		if ( ! empty( $g['sitemaps'] ) ) {
			echo '<h3>' . esc_html__( 'Sitemaps', 'index-sentinel' ) . '</h3><table class="idxs-table"><thead><tr><th>' . esc_html__( 'Sitemap', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Last read by Google', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Status', 'index-sentinel' ) . '</th></tr></thead><tbody>';
			foreach ( $g['sitemaps'] as $sm ) {
				/* translators: %d: number of errors. */
				$st = $sm['errors'] ? $this->pill( sprintf( __( '%d errors', 'index-sentinel' ), $sm['errors'] ), 'bad' ) : ( $sm['pending'] ? $this->pill( __( 'Pending', 'index-sentinel' ), 'warn' ) : $this->pill( __( 'OK', 'index-sentinel' ), 'good' ) );
				echo '<tr><td><code>' . esc_html( str_replace( home_url(), '', $sm['path'] ) ) . '</code></td><td>' . esc_html( $sm['downloaded'] ? $this->ago( strtotime( $sm['downloaded'] ) ) : __( 'not yet', 'index-sentinel' ) ) . '</td><td>' . $st . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '</tbody></table>';
		}
		echo '</section>';

		$unknown = isset( $g['analytics']['unknown'] ) ? $g['analytics']['unknown'] : array();
		$this->card_open( __( 'Unknown URLs showing in Google', 'index-sentinel' ), 'warning' );
		echo '<p class="idxs-muted">' . esc_html__( 'URLs that got impressions but are not your pages and do not match a known spam pattern. A new spam injection shows up here first.', 'index-sentinel' ) . '</p>';
		if ( ! $unknown ) {
			echo '<div class="idxs-empty"><span class="dashicons dashicons-yes-alt" aria-hidden="true"></span><p>' . esc_html__( 'None. Google only shows your own pages (and known, already-removed spam).', 'index-sentinel' ) . '</p></div>';
		} else {
			echo '<table class="idxs-table"><thead><tr><th>URL</th><th>' . esc_html__( 'Impressions', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Clicks', 'index-sentinel' ) . '</th></tr></thead><tbody>';
			foreach ( $unknown as $u ) {
				echo '<tr><td><a href="' . esc_url( $u['url'] ) . '" target="_blank" rel="noopener">' . esc_html( str_replace( home_url(), '', $u['url'] ) ) . '</a></td><td class="num">' . esc_html( $u['impressions'] ) . '</td><td class="num">' . esc_html( $u['clicks'] ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</section>';

		$urls = isset( $g['urls'] ) ? (array) $g['urls'] : array();
		$this->card_open( __( 'Your pages in Google', 'index-sentinel' ), 'admin-page' );
		if ( $urls ) {
			uasort(
				$urls,
				static function ( $a, $b ) {
					return strcmp( $a['verdict'], $b['verdict'] );
				}
			);
			echo '<table class="idxs-table"><thead><tr><th>' . esc_html__( 'Page', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Status', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Google says', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Last crawl', 'index-sentinel' ) . '</th></tr></thead><tbody>';
			foreach ( $urls as $url => $u ) {
				if ( 'PASS' === $u['verdict'] ) {
					$pill = $this->pill( __( 'Indexed', 'index-sentinel' ), 'good' );
				} elseif ( 'PENDING' === $u['verdict'] ) {
					$pill = $this->pill( __( 'Not checked yet', 'index-sentinel' ), 'muted' );
				} else {
					$pill = $this->pill( __( 'Not indexed', 'index-sentinel' ), 'FAIL' === $u['verdict'] ? 'bad' : 'warn' );
				}
				$path = str_replace( home_url(), '', $url );
				echo '<tr><td><a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( $path ? $path : '/' ) . '</a></td><td>' . $pill . '</td><td>' . esc_html( $u['coverage'] ) . '</td><td>' . esc_html( $u['crawl'] ? $this->ago( strtotime( $u['crawl'] ) ) : '–' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '</tbody></table>';
		} else {
			echo '<p class="idxs-muted">' . esc_html__( 'Not loaded yet.', 'index-sentinel' ) . '</p>';
		}
		echo '</section>';

		if ( Settings::spam_patterns() ) {
			$hist = isset( $g['spam_history'] ) ? (array) $g['spam_history'] : array();
			$this->card_open( __( 'Known spam still showing in Google', 'index-sentinel' ), 'trash' );
			/* translators: 1: number of spam URLs, 2: impressions. */
			echo '<p>' . esc_html( sprintf( __( '%1$d known spam URLs got impressions in the last 28 days (%2$d impressions). If they answer 410 or 404, this number keeps falling.', 'index-sentinel' ), isset( $g['analytics']['spam_count'] ) ? $g['analytics']['spam_count'] : 0, isset( $g['analytics']['totals']['spam'][1] ) ? $g['analytics']['totals']['spam'][1] : 0 ) ) . '</p>';
			echo $this->bars( wp_list_pluck( $hist, 'spam_pages' ), 'red' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</section>';
		}
	}

	/**
	 * Traffic tab.
	 */
	private function tab_traffic() {
		$t = Store::get( 'traffic', array() );
		$this->card_open( __( 'Traffic & spam (server access logs, last 30 days)', 'index-sentinel' ), 'chart-area', $this->run_button( 'traffic', __( 'Read logs now', 'index-sentinel' ) ) );
		if ( ! empty( $t['error'] ) || empty( $t['days'] ) ) {
			echo '<p class="idxs-muted">' . esc_html( ! empty( $t['error'] ) ? $t['error'] : __( 'Not read yet.', 'index-sentinel' ) ) . '</p></section>';
			return;
		}
		$days = $t['days'];
		$sum  = static function ( $k ) use ( $days ) {
			return array_sum( wp_list_pluck( $days, $k ) );
		};
		/* translators: 1: log file names, 2: time ago. */
		echo '<p class="idxs-muted">' . esc_html( sprintf( __( 'Source: %1$s · updated %2$s', 'index-sentinel' ), implode( ', ', $t['files'] ), $this->ago( $t['updated'] ) ) ) . '</p>';
		echo '<div class="idxs-stats idxs-stats--wide">';
		echo '<div><b>' . esc_html( number_format_i18n( $sum( 'total' ) ) ) . '</b><span>' . esc_html__( 'Requests', 'index-sentinel' ) . '</span></div>';
		echo '<div><b class="is-good">' . esc_html( number_format_i18n( $sum( 'google_gone' ) ) ) . '</b><span>' . esc_html__( 'Spam URLs Google found gone', 'index-sentinel' ) . '</span></div>';
		echo '<div><b>' . esc_html( number_format_i18n( $sum( 'spam' ) ) ) . '</b><span>' . esc_html__( 'Spam URL hits (all bots)', 'index-sentinel' ) . '</span></div>';
		echo '<div><b class="is-warn">' . esc_html( number_format_i18n( $sum( 'probes' ) ) ) . '</b><span>' . esc_html__( 'Hacker probes', 'index-sentinel' ) . '</span></div>';
		echo '<div><b>' . esc_html( number_format_i18n( $sum( 'ai' ) ) ) . '</b><span>' . esc_html__( 'AI search bot visits', 'index-sentinel' ) . '</span></div></div>';
		echo '<div class="idxs-grid idxs-grid--2"><div><h3>' . esc_html__( 'Googlebot finding spam URLs gone (per day)', 'index-sentinel' ) . '</h3>' . $this->bars( wp_list_pluck( $days, 'google_gone' ), 'green' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<div><h3>' . esc_html__( 'Hacker probes (per day)', 'index-sentinel' ) . '</h3>' . $this->bars( wp_list_pluck( $days, 'probes' ), 'red' ) . '</div></div></section>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		echo '<div class="idxs-grid">';
		$this->card_open( __( 'Bots that visited', 'index-sentinel' ), 'admin-site-alt3' );
		$this->kv_table( $t['bots'], false );
		echo '</section>';
		$this->card_open( __( 'Your pages Googlebot crawled', 'index-sentinel' ), 'google' );
		$this->kv_table( $t['google_pages'] );
		echo '</section>';
		$this->card_open( __( 'Most requested missing pages (404)', 'index-sentinel' ), 'dismiss' );
		$this->kv_table( $t['top404'] );
		echo '</section>';
		$this->card_open( __( 'Most active probing IPs', 'index-sentinel' ), 'privacy' );
		$this->kv_table( $t['top_probers'] );
		echo '</section></div>';
	}

	/**
	 * Activity tab.
	 */
	private function tab_activity() {
		$this->card_open( __( 'Activity log', 'index-sentinel' ), 'list-view' );
		$rows = Store::events( array( 'login_ok', 'login_fail', 'lockout', 'admin_change', 'blocked', 'alert', 'quarantine', 'scan' ), 100 );
		if ( ! $rows ) {
			echo '<p class="idxs-muted">' . esc_html__( 'No events yet.', 'index-sentinel' ) . '</p></section>';
			return;
		}
		$tones = array( 'login_ok' => 'good', 'login_fail' => 'warn', 'lockout' => 'bad', 'admin_change' => 'bad', 'blocked' => 'warn', 'alert' => 'bad', 'quarantine' => 'warn', 'scan' => 'muted' );
		$names = array(
			'login_ok'     => __( 'Login', 'index-sentinel' ),
			'login_fail'   => __( 'Failed login', 'index-sentinel' ),
			'lockout'      => __( 'Lockout', 'index-sentinel' ),
			'admin_change' => __( 'Admin change', 'index-sentinel' ),
			'blocked'      => __( 'Blocked', 'index-sentinel' ),
			'alert'        => __( 'Alert', 'index-sentinel' ),
			'quarantine'   => __( 'Quarantine', 'index-sentinel' ),
			'scan'         => __( 'Scan', 'index-sentinel' ),
		);
		echo '<table class="idxs-table"><thead><tr><th>' . esc_html__( 'When', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Event', 'index-sentinel' ) . '</th><th>' . esc_html__( 'Details', 'index-sentinel' ) . '</th><th>IP</th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$ctx  = json_decode( (string) $r['context'], true );
			$info = isset( $ctx['user'] ) ? $ctx['user'] : ( isset( $ctx['uri'] ) ? $ctx['uri'] : '' );
			echo '<tr><td>' . esc_html( $this->ago( strtotime( $r['created_at'] . ' UTC' ) ) ) . '</td><td>' . $this->pill( isset( $names[ $r['type'] ] ) ? $names[ $r['type'] ] : $r['type'], isset( $tones[ $r['type'] ] ) ? $tones[ $r['type'] ] : 'muted' ) . '</td><td>' . esc_html( $r['message'] . ( $info ? ' · ' . $info : '' ) ) . '</td><td><code>' . esc_html( $r['ip'] ) . '</code></td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</tbody></table></section>';
	}

	/**
	 * Hardening tab.
	 */
	private function tab_hardening() {
		$this->card_open( __( 'Security checklist', 'index-sentinel' ), 'lock', $this->run_button( 'hardening', __( 'Re-check', 'index-sentinel' ) ) );
		echo '<ul class="idxs-checks">';
		foreach ( $this->hardening() as $c ) {
			$state = null === $c['ok'] ? 'unknown' : ( $c['ok'] ? 'ok' : 'fail' );
			$icon  = array( 'ok' => 'yes-alt', 'fail' => 'warning', 'unknown' => 'editor-help' );
			echo '<li class="is-' . esc_attr( $state ) . '"><span class="dashicons dashicons-' . esc_attr( $icon[ $state ] ) . '" aria-hidden="true"></span><div><b>' . esc_html( $c['label'] ) . '</b><p>' . esc_html( $c['why'] );
			if ( 'fail' === $state ) {
				echo ' <em>' . esc_html__( 'Fix:', 'index-sentinel' ) . ' ' . esc_html( $c['fix'] ) . '</em>';
			} elseif ( 'unknown' === $state ) {
				echo ' <em>' . esc_html__( 'Cannot be checked automatically on this server.', 'index-sentinel' ) . '</em>';
			}
			echo '</p></div></li>';
		}
		echo '</ul></section>';
	}

	/**
	 * Checkbox row.
	 *
	 * @param string $key   Setting key.
	 * @param string $label Label.
	 * @param string $help  Help text.
	 */
	private function checkbox( $key, $label, $help = '' ) {
		echo '<label class="idxs-toggle"><input type="checkbox" name="index_sentinel[' . esc_attr( $key ) . ']" value="1" ' . checked( (int) Settings::get( $key ), 1, false ) . '><span><b>' . esc_html( $label ) . '</b>' . ( $help ? '<small>' . esc_html( $help ) . '</small>' : '' ) . '</span></label>';
	}

	/**
	 * Settings tab.
	 */
	private function tab_settings() {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="idxs-form">';
		wp_nonce_field( 'index_sentinel_action' );
		echo '<input type="hidden" name="action" value="index_sentinel_action"><input type="hidden" name="do" value="settings">';

		echo '<div class="idxs-grid idxs-grid--2">';
		$this->card_open( __( 'Modules', 'index-sentinel' ), 'screenoptions' );
		$this->checkbox( 'module_scanner', __( 'Daily malware & integrity scan', 'index-sentinel' ) );
		$this->checkbox( 'module_cloaking', __( 'Hourly Googlebot cloaking check', 'index-sentinel' ) );
		$this->checkbox( 'module_google', __( 'Google index monitoring', 'index-sentinel' ), __( 'Needs Site Kit by Google connected to Search Console.', 'index-sentinel' ) );
		$this->checkbox( 'module_traffic', __( 'Access log analysis', 'index-sentinel' ) );
		$this->checkbox( 'module_firewall', __( 'Block exploit probes (403)', 'index-sentinel' ) );
		$this->checkbox( 'module_login', __( 'Login protection (lockout)', 'index-sentinel' ) );
		echo '</section>';

		$this->card_open( __( 'Hardening', 'index-sentinel' ), 'lock' );
		$this->checkbox( 'harden_users_api', __( 'Hide usernames from the public REST API', 'index-sentinel' ) );
		$this->checkbox( 'harden_author', __( 'Block ?author= username scans', 'index-sentinel' ) );
		$this->checkbox( 'harden_xmlrpc', __( 'Disable XML-RPC', 'index-sentinel' ), __( 'Leave off if you use the Jetpack app or remote publishing.', 'index-sentinel' ) );
		$this->checkbox( 'harden_version', __( 'Hide the WordPress version', 'index-sentinel' ) );
		$this->checkbox( 'harden_login_msg', __( 'Generic login error messages', 'index-sentinel' ) );
		echo '</section>';

		$this->card_open( __( 'Spam URL clean-up', 'index-sentinel' ), 'trash' );
		echo '<p class="idxs-muted">' . esc_html__( 'If your site was hit by an SEO spam hack, list the pattern of its fake URLs (one PHP regular expression per line, matched against the URL path). Index Sentinel then tracks how fast Google drops them and can answer them with "410 Gone".', 'index-sentinel' ) . '</p>';
		echo '<textarea name="index_sentinel[spam_patterns]" rows="4" spellcheck="false" placeholder="' . esc_attr( Settings::JAPANESE_HACK_PATTERN ) . '">' . esc_textarea( (string) Settings::get( 'spam_patterns' ) ) . '</textarea>';
		$this->checkbox( 'spam_410', __( 'Answer matching URLs with "410 Gone"', 'index-sentinel' ), __( 'Tells Google the pages are gone for good. Only enable once you are sure the pattern never matches a real page.', 'index-sentinel' ) );
		echo '</section>';

		$this->card_open( __( 'Alerts & login', 'index-sentinel' ), 'email' );
		$this->checkbox( 'alerts', __( 'Email me when something serious is found', 'index-sentinel' ) );
		echo '<label>' . esc_html__( 'Alert email', 'index-sentinel' ) . '<input type="email" name="index_sentinel[alert_email]" value="' . esc_attr( Settings::get( 'alert_email' ) ) . '"></label>';
		echo '<div class="idxs-row"><label>' . esc_html__( 'Failed attempts allowed (15 min)', 'index-sentinel' ) . '<input type="number" min="3" max="20" name="index_sentinel[max_attempts]" value="' . esc_attr( Settings::get( 'max_attempts' ) ) . '"></label>';
		echo '<label>' . esc_html__( 'Lockout minutes', 'index-sentinel' ) . '<input type="number" min="5" max="1440" name="index_sentinel[lockout_minutes]" value="' . esc_attr( Settings::get( 'lockout_minutes' ) ) . '"></label></div>';
		$this->checkbox( 'trust_cloudflare', __( 'Site is behind Cloudflare', 'index-sentinel' ), __( 'Uses the real visitor IP from Cloudflare (only for requests that really come from Cloudflare).', 'index-sentinel' ) );
		echo '</section>';

		$this->card_open( __( 'Access log', 'index-sentinel' ), 'media-text' );
		$found = ( new LogReader() )->files();
		/* translators: %s: list of files. */
		echo '<p class="idxs-muted">' . esc_html( $found ? sprintf( __( 'Found: %s', 'index-sentinel' ), implode( ', ', array_map( 'basename', $found ) ) ) : __( 'No log found automatically. Ask your host where the access log is and enter the path (a * wildcard is allowed).', 'index-sentinel' ) ) . '</p>';
		echo '<label>' . esc_html__( 'Custom log path (optional)', 'index-sentinel' ) . '<input type="text" name="index_sentinel[log_path]" value="' . esc_attr( Settings::get( 'log_path' ) ) . '" placeholder="/home/user/logs/example.com-ssl_log-*.gz"></label>';
		echo '</section>';

		$this->card_open( __( 'Data', 'index-sentinel' ), 'database' );
		$this->checkbox( 'delete_on_uninstall', __( 'Delete all Index Sentinel data when the plugin is deleted', 'index-sentinel' ) );
		echo '</section></div>';

		echo '<p><button type="submit" class="idxs-btn idxs-btn--primary">' . esc_html__( 'Save settings', 'index-sentinel' ) . '</button></p></form>';

		echo '<div class="idxs-card idxs-card--flat"><p>';
		echo $this->form( 'add_preset', __( 'Add the common "Japanese keyword hack" pattern', 'index-sentinel' ), 'idxs-btn' ) . ' '; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $this->form( 'test_email', __( 'Send a test alert email', 'index-sentinel' ), 'idxs-btn' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '</p>';
		$next = wp_next_scheduled( 'index_sentinel_daily' );
		/* translators: %s: date and time. */
		echo '<p class="idxs-muted">' . esc_html( sprintf( __( 'Next automatic daily check: %s.', 'index-sentinel' ), $next ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next ) : __( 'not scheduled', 'index-sentinel' ) ) ) . ' WP-CLI: <code>wp index-sentinel scan|google|traffic|cloak|daily</code></p></div>';
	}

	/**
	 * WP dashboard widget.
	 */
	public function widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'index_sentinel_widget',
			__( 'Index Sentinel', 'index-sentinel' ),
			function () {
				$s    = $this->score();
				$tone = $s['score'] >= 85 ? 'good' : ( $s['score'] >= 60 ? 'warn' : 'bad' );
				echo '<div class="idxs idxs-widget"><b class="idxs-big is-' . esc_attr( $tone ) . '">' . esc_html( $s['score'] ) . '/100</b> ';
				/* translators: %d: number of critical issues. */
				echo $s['critical'] ? $this->pill( sprintf( _n( '%d critical issue', '%d critical issues', $s['critical'], 'index-sentinel' ), $s['critical'] ), 'bad' ) : $this->pill( __( 'No critical issues', 'index-sentinel' ), 'good' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo ' <a class="idxs-btn idxs-btn--sm" href="' . esc_url( admin_url( 'admin.php?page=' . self::SLUG ) ) . '">' . esc_html__( 'Open dashboard', 'index-sentinel' ) . '</a></div>';
			}
		);
	}
}
