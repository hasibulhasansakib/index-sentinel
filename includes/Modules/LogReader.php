<?php
/**
 * Access log reader.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Builds a 30-day traffic picture from the server access log (no per-request logging in PHP):
 * spam URL hits, how many Googlebot re-checked and found gone (= de-index progress),
 * search and AI bot visits, hacker probes and the most common missing pages.
 *
 * Log files are found automatically on cPanel hosting (~/logs/<domain>*.gz and ~/access-logs/<domain>*);
 * any other host can set a path (or glob pattern) in Settings. Common/combined log format, plain or .gz.
 */
final class LogReader {

	/**
	 * Bot names and user-agent patterns.
	 *
	 * @return array
	 */
	private function bots() {
		return array(
			'Googlebot'     => '#Googlebot#i',
			'Bingbot'       => '#bingbot#i',
			'ChatGPT'       => '#GPTBot|OAI-SearchBot|ChatGPT-User#i',
			'Claude'        => '#ClaudeBot|Claude-SearchBot|Claude-User#i',
			'Perplexity'    => '#PerplexityBot#i',
			'Applebot'      => '#Applebot#i',
			'Other bots'    => '#bot|crawl|spider|slurp#i',
		);
	}

	/**
	 * Candidate log files.
	 *
	 * @return string[]
	 */
	public function files() {
		$custom = trim( (string) Settings::get( 'log_path' ) );
		if ( '' !== $custom ) {
			return array_values( array_filter( (array) glob( $custom ), 'is_readable' ) );
		}
		$host  = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$homes = array_unique( array_filter( array( dirname( untrailingslashit( ABSPATH ) ), getenv( 'HOME' ), dirname( dirname( untrailingslashit( ABSPATH ) ) ) ) ) );
		$out   = array();
		foreach ( $homes as $home ) {
			foreach ( array( 'now', 'first day of last month' ) as $when ) {
				$tag = gmdate( 'M-Y', strtotime( $when ) );
				foreach ( (array) glob( "{$home}/logs/{$host}*-{$tag}.gz" ) as $f ) {
					$out[] = $f;
				}
			}
			foreach ( (array) glob( "{$home}/access-logs/{$host}*" ) as $f ) {
				$out[] = $f;
			}
		}
		return array_values( array_unique( array_filter( $out, 'is_readable' ) ) );
	}

	/**
	 * Parse the logs and store the 30-day summary.
	 *
	 * @return array
	 */
	public function run() {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$files = $this->files();
		if ( ! $files ) {
			$data = array(
				'updated' => time(),
				'error'   => __( 'No readable access log found. On cPanel hosting it is found automatically; elsewhere set the log file path in Settings.', 'index-sentinel' ),
			);
			Store::set( 'traffic', $data );
			return $data;
		}
		$cutoff  = strtotime( '-30 days' );
		$days    = array();
		$n404    = array();
		$probers = array();
		$bots    = array_fill_keys( array_keys( $this->bots() ), 0 );
		$gpages  = array();
		$probe   = '#(/wp-login\.php|/xmlrpc\.php|/\.env|/\.git|/wp-config|phpmyadmin|/cgi-bin|\.(sql|zip|tar|bak)$|/wp-content/plugins/[^/]+/readme\.txt)#i';

		foreach ( $files as $file ) {
			$gz = '.gz' === substr( $file, -3 );
			$fh = $gz ? gzopen( $file, 'r' ) : fopen( $file, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
			if ( ! $fh ) {
				continue;
			}
			while ( false !== ( $line = $gz ? gzgets( $fh, 8192 ) : fgets( $fh, 8192 ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
				if ( ! preg_match( '#^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?#', $line, $m ) ) {
					continue;
				}
				$ts = strtotime( $m[2] );
				if ( ! $ts || $ts < $cutoff ) {
					continue;
				}
				$ip     = $m[1];
				$method = $m[3];
				$path   = (string) strtok( $m[4], '?' );
				$code   = $m[5];
				$ua     = isset( $m[6] ) ? $m[6] : '';
				$day    = gmdate( 'Y-m-d', $ts );
				if ( ! isset( $days[ $day ] ) ) {
					$days[ $day ] = array( 'total' => 0, 'spam' => 0, 'google_gone' => 0, 'probes' => 0, 'e404' => 0, 'google' => 0, 'ai' => 0 );
				}
				$days[ $day ]['total']++;

				$is_google = (bool) preg_match( '#Googlebot#i', $ua );
				$is_spam   = Settings::is_spam_path( $path );
				if ( $is_google ) {
					$days[ $day ]['google']++;
				}
				if ( preg_match( '#GPTBot|OAI-SearchBot|ChatGPT-User|ClaudeBot|Claude-SearchBot|PerplexityBot#i', $ua ) ) {
					$days[ $day ]['ai']++;
				}
				foreach ( $this->bots() as $name => $re ) {
					if ( preg_match( $re, $ua ) ) {
						$bots[ $name ]++;
						break;
					}
				}
				if ( $is_spam ) {
					$days[ $day ]['spam']++;
					if ( $is_google && in_array( $code, array( '404', '410' ), true ) ) {
						$days[ $day ]['google_gone']++;
					}
				} elseif ( $is_google && '200' === $code && ! preg_match( '#\.(css|js|png|jpe?g|webp|svg|woff2?|ico|xml|txt)$#i', $path ) ) {
					$gpages[ $path ] = isset( $gpages[ $path ] ) ? $gpages[ $path ] + 1 : 1;
				}
				if ( preg_match( $probe, $path ) && ! ( 'GET' === $method && '/wp-login.php' === $path ) ) {
					$days[ $day ]['probes']++;
					$probers[ $ip ] = isset( $probers[ $ip ] ) ? $probers[ $ip ] + 1 : 1;
				}
				if ( '404' === $code && ! $is_spam ) {
					$days[ $day ]['e404']++;
					$n404[ $path ] = isset( $n404[ $path ] ) ? $n404[ $path ] + 1 : 1;
				}
			}
			$gz ? gzclose( $fh ) : fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		}
		ksort( $days );
		arsort( $n404 );
		arsort( $probers );
		arsort( $gpages );

		// On shared hosting, requests relayed by the host's own proxy show the server's address instead of the visitor.
		$server = (string) gethostbyname( (string) gethostname() );
		$prefix = preg_match( '/^(\d+\.\d+\.\d+)\./', $server, $sm ) ? $sm[1] . '.' : '';
		$named  = array();
		foreach ( array_slice( $probers, 0, 10, true ) as $pip => $cnt ) {
			$label           = ( $prefix && 0 === strpos( (string) $pip, $prefix ) ) ? $pip . ' ' . __( '(host proxy, real IP hidden)', 'index-sentinel' ) : (string) $pip;
			$named[ $label ] = $cnt;
		}

		$data = array(
			'updated'      => time(),
			'files'        => array_map( 'basename', $files ),
			'days'         => $days,
			'top404'       => array_slice( $n404, 0, 15, true ),
			'top_probers'  => $named,
			'bots'         => $bots,
			'google_pages' => array_slice( $gpages, 0, 20, true ),
		);
		Store::set( 'traffic', $data );
		return $data;
	}
}
