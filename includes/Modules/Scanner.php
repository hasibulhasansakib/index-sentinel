<?php
/**
 * Malware, integrity and cloaking scanner.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * What it checks:
 * 1. WordPress core files against the official checksums (changed files and files WordPress does not ship).
 * 2. Plugins from WordPress.org against their official checksums.
 * 3. Everything else you run (custom plugins, themes, must-use plugins) against a trusted baseline.
 * 4. A malware signature scan of every PHP file not already proven clean, plus any PHP inside uploads.
 * 5. Tricks used by SEO spam hacks: PHP hidden in images or fonts, hidden PHP files, folders nested in themselves.
 * 6. The database: injected scripts, Japanese spam text, unknown administrators.
 * 7. Cloaking: the homepage as Googlebot sees it, and how a spam-style URL answers.
 */
final class Scanner {

	/**
	 * Folders never walked (caches, backups, our own quarantine).
	 */
	const SKIP_DIRS = array( 'cache', 'litespeed', 'upgrade', 'upgrade-temp-backup', 'node_modules', 'index-sentinel-quarantine', 'updraft', 'ai1wm-backups', 'wpvividbackups', 'backups-dup-lite', 'backup-db' );

	/**
	 * Findings of the current run.
	 *
	 * @var array
	 */
	private $findings = array();

	/**
	 * Files examined.
	 *
	 * @var int
	 */
	private $files = 0;

	/**
	 * WordPress.org plugin folders verified by checksum.
	 *
	 * @var string[]
	 */
	private $org_dirs = array();

	/**
	 * Malware signatures. Letters are wrapped in [] (for example ev[a]l) so this file does not itself contain
	 * the trigger words; some server antivirus tools would otherwise flag the scanner as malware.
	 *
	 * @return array name => regex
	 */
	public static function signatures() {
		$input = '\$_(POST|GET|REQUEST|COOKIE)';
		$sigs  = array(
			'eval-of-decoded-code'  => '#ev[a]l\s*\(\s*(bas[e]64_decode|gzinf[l]ate|gzuncom[p]ress|str_ro[t]13|gzdeco[d]e)\s*\(#i',
			'assert-on-user-input'  => '#ass[e]rt\s*\(\s*' . $input . '#i',
			'preg-replace-eval'     => '#preg_rep[l]ace\s*\(\s*[\'"][^\'"]*/e[\'"]#i',
			'create-function-input' => '#create_fun[c]tion\s*\([^)]*' . $input . '#i',
			'shell-on-user-input'   => '#(sys[t]em|shell_ex[e]c|pass[t]hru|ex[e]c|po[p]en|proc_op[e]n)\s*\(\s*' . $input . '#i',
			'include-user-input'    => '#(include|require)(_once)?\s*\(?\s*' . $input . '#i',
			'hex-variable-call'     => '#\$\{\s*["\']\\\\x[0-9a-f]{2}#i',
			'huge-encoded-string'   => '#[\'"][A-Za-z0-9+/=]{2000,}[\'"]#',
			'known-web-shell'       => '#(Files[M]an|W[S]O\s?[0-9.]+|c9[9]shell|r5[7]shell|b3[7]4k|Indo[X]ploit|\{-\.-!!!\})#',
			'remote-spam-injector'  => '#(file_get_con[t]ents|curl_ex[e]c)\s*\(\s*["\']https?://[^"\']+\.(xyz|top|ru|cn|tk)/#i',
		);
		/**
		 * Filter the malware signatures (name => PCRE pattern).
		 *
		 * @param array $sigs Signatures.
		 */
		return (array) apply_filters( 'index_sentinel_signatures', $sigs );
	}

	/**
	 * Run the full scan and store the result.
	 *
	 * @return array
	 */
	public function run() {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$start          = microtime( true );
		$this->findings = array();
		$this->files    = 0;

		$clean = array_merge( $this->core(), $this->org_plugins() );
		$this->baseline();
		$this->signature_scan( $clean );
		$this->layout_tricks();
		$this->database();
		if ( Settings::get( 'module_cloaking' ) ) {
			$cloak = $this->cloaking_check();
			Store::set( 'cloak', $cloak );
			foreach ( $cloak['problems'] as $p ) {
				$this->add( 'critical', 'cloaking', home_url( '/' ), $p );
			}
		}

		/**
		 * Filter scan findings before they are saved (add-ons can add or remove findings).
		 *
		 * @param array $findings Findings.
		 */
		$this->findings = (array) apply_filters( 'index_sentinel_scan_findings', $this->findings );

		$result = array(
			'time'     => time(),
			'duration' => round( microtime( true ) - $start, 1 ),
			'files'    => $this->files,
			'findings' => $this->findings,
			'counts'   => array_count_values( wp_list_pluck( $this->findings, 'severity' ) ),
		);
		Store::set( 'scan', $result );
		/* translators: 1: files scanned, 2: number of findings. */
		Store::log( 'scan', sprintf( __( 'Scan finished: %1$d files, %2$d findings', 'index-sentinel' ), $this->files, count( $this->findings ) ), $this->findings ? 'warning' : 'info' );
		return $result;
	}

	/**
	 * Record a finding.
	 *
	 * @param string $severity critical|warning|notice.
	 * @param string $type     Finding type.
	 * @param string $path     File or location.
	 * @param string $detail   Explanation.
	 */
	private function add( $severity, $type, $path, $detail ) {
		$this->findings[] = array(
			'severity' => $severity,
			'type'     => $type,
			'path'     => self::relative( $path ),
			'detail'   => $detail,
		);
	}

	/**
	 * Path relative to ABSPATH.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private static function relative( $path ) {
		$rel = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ), '/' );
		return $rel ? $rel : $path;
	}

	/**
	 * Core files vs. official checksums.
	 *
	 * @return array Verified-clean absolute paths (as keys).
	 */
	private function core() {
		require_once ABSPATH . 'wp-admin/includes/update.php';
		global $wp_version, $wp_local_package;
		$sums = get_core_checksums( $wp_version, empty( $wp_local_package ) ? 'en_US' : $wp_local_package );
		if ( ! is_array( $sums ) ) {
			$this->add( 'notice', 'core', 'WordPress', __( 'Could not download the official core checksums. The core check was skipped this time.', 'index-sentinel' ) );
			return array();
		}
		$clean = array();
		foreach ( $sums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) || ! file_exists( ABSPATH . $file ) ) {
				continue;
			}
			$this->files++;
			if ( md5_file( ABSPATH . $file ) !== $md5 ) {
				$this->add( 'critical', 'core-modified', ABSPATH . $file, __( 'WordPress core file differs from the official version.', 'index-sentinel' ) );
			} else {
				$clean[ wp_normalize_path( ABSPATH . $file ) ] = true;
			}
		}
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( $this->walk( ABSPATH . $dir ) as $abs ) {
				if ( isset( $sums[ self::relative( $abs ) ] ) ) {
					continue;
				}
				$is_php = (bool) preg_match( '/\.(php\d?|phtml|phar|inc)$/i', $abs );
				if ( $is_php ) {
					$this->add( 'critical', 'core-unknown', $abs, __( 'Unknown PHP file inside WordPress core folders, a typical backdoor location.', 'index-sentinel' ) );
				} elseif ( 'error_log' !== basename( $abs ) ) {
					$this->add( 'notice', 'core-unknown', $abs, __( 'File that WordPress does not ship (often left over from an older version).', 'index-sentinel' ) );
				}
			}
		}
		foreach ( (array) glob( ABSPATH . '*.php' ) as $abs ) {
			if ( $abs && ! isset( $sums[ basename( $abs ) ] ) && 'wp-config.php' !== basename( $abs ) ) {
				$this->add( 'warning', 'root-unknown', $abs, __( 'Extra PHP file in the site root. Check that you know what it is.', 'index-sentinel' ) );
			}
		}
		return $clean;
	}

	/**
	 * WordPress.org plugins vs. official checksums.
	 *
	 * @return array Verified-clean absolute paths (as keys).
	 */
	private function org_plugins() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$clean = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				continue;
			}
			$res = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $data['Version'] ) . '.json', array( 'timeout' => 20 ) );
			if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
				continue; // Not on WordPress.org: covered by the baseline check.
			}
			$json  = json_decode( wp_remote_retrieve_body( $res ), true );
			$files = isset( $json['files'] ) ? (array) $json['files'] : array();
			$dir   = WP_PLUGIN_DIR . '/' . $slug . '/';

			$this->org_dirs[] = wp_normalize_path( WP_PLUGIN_DIR . '/' . $slug );
			foreach ( $files as $rel => $sum ) {
				if ( ! file_exists( $dir . $rel ) ) {
					continue;
				}
				$this->files++;
				if ( in_array( md5_file( $dir . $rel ), (array) $sum['md5'], true ) ) {
					$clean[ wp_normalize_path( $dir . $rel ) ] = true;
				} elseif ( preg_match( '/\.php$/i', $rel ) ) {
					/* translators: 1: plugin name, 2: version. */
					$this->add( 'critical', 'plugin-modified', $dir . $rel, sprintf( __( 'File differs from the official %1$s %2$s release.', 'index-sentinel' ), $data['Name'], $data['Version'] ) );
				}
			}
			foreach ( $this->walk( $dir ) as $abs ) {
				$rel = substr( wp_normalize_path( $abs ), strlen( wp_normalize_path( $dir ) ) );
				if ( ! isset( $files[ $rel ] ) && preg_match( '/\.(php\d?|phtml|phar)$/i', $abs ) ) {
					/* translators: %s: plugin name. */
					$this->add( 'warning', 'plugin-unknown', $abs, sprintf( __( 'PHP file that is not part of the official %s release.', 'index-sentinel' ), $data['Name'] ) );
				}
			}
		}
		return $clean;
	}

	/**
	 * Custom code: new or changed files since the last accepted baseline.
	 */
	private function baseline() {
		$roots = array_filter( array( WPMU_PLUGIN_DIR, get_theme_root() ) );
		foreach ( (array) glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR ) as $dir ) {
			if ( $dir && ! in_array( wp_normalize_path( $dir ), $this->org_dirs, true ) ) {
				$roots[] = $dir;
			}
		}
		$old = Store::get( 'baseline', array() );
		$new = array();
		foreach ( $roots as $root ) {
			foreach ( $this->walk( $root ) as $abs ) {
				if ( preg_match( '/\.(php\d?|phtml|phar|js)$/i', $abs ) || '.htaccess' === basename( $abs ) ) {
					$new[ self::relative( $abs ) ] = md5_file( $abs );
				}
			}
		}
		if ( $old ) {
			foreach ( $new as $key => $md5 ) {
				if ( ! isset( $old[ $key ] ) ) {
					$this->add( 'notice', 'file-new', ABSPATH . $key, __( 'New file since you last marked files as trusted (normal after installing or updating).', 'index-sentinel' ) );
				} elseif ( $old[ $key ] !== $md5 ) {
					$this->add( 'notice', 'file-changed', ABSPATH . $key, __( 'File changed since you last marked files as trusted (normal after updating).', 'index-sentinel' ) );
				}
			}
		}
		Store::set( 'baseline_pending', $new );
		if ( ! $old ) {
			Store::set( 'baseline', $new );
		}
	}

	/**
	 * Accept the current files as trusted.
	 */
	public static function accept_baseline() {
		$pending = Store::get( 'baseline_pending', array() );
		if ( $pending ) {
			Store::set( 'baseline', $pending );
		}
	}

	/**
	 * Signature scan of every PHP file not verified by checksum.
	 *
	 * @param array $clean Verified files.
	 */
	private function signature_scan( $clean ) {
		$sigs = self::signatures();
		foreach ( $this->walk( WP_CONTENT_DIR, self::SKIP_DIRS ) as $abs ) {
			$norm = wp_normalize_path( $abs );
			if ( isset( $clean[ $norm ] ) ) {
				continue;
			}
			$is_php = (bool) preg_match( '/\.(php\d?|phtml|phar|inc)$/i', $abs );
			if ( $is_php && false !== strpos( $norm, '/wp-content/uploads/' ) && 'index.php' !== basename( $abs ) ) {
				$this->add( 'critical', 'php-in-uploads', $abs, __( 'PHP file inside the uploads folder. Uploads should only hold media.', 'index-sentinel' ) );
			}
			if ( ! $is_php || filesize( $abs ) > 3 * MB_IN_BYTES ) {
				continue;
			}
			$this->files++;
			$code = (string) file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			foreach ( $sigs as $name => $re ) {
				if ( preg_match( $re, $code ) ) {
					/* translators: %s: signature name. */
					$this->add( 'critical', 'malware-signature', $abs, sprintf( __( 'Matches the malware pattern "%s".', 'index-sentinel' ), $name ) );
					break;
				}
			}
		}
	}

	/**
	 * PHP hidden in media/font files, hidden PHP files and self-nested folders.
	 */
	private function layout_tricks() {
		$skip = array_merge( self::SKIP_DIRS, array( 'vendor', 'third-party', 'vendor_prefixed' ) );
		foreach ( $this->walk( ABSPATH, $skip ) as $abs ) {
			$name = basename( $abs );
			if ( preg_match( '/\.(jpe?g|png|gif|ico|ttf|woff2?|txt)$/i', $name ) && filesize( $abs ) < 2 * MB_IN_BYTES ) {
				$head = (string) file_get_contents( $abs, false, null, 0, 4096 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( preg_match( '/<\?php|ev[a]l\s*\(|bas[e]64_decode\s*\(/i', $head ) ) {
					$this->add( 'critical', 'disguised-php', $abs, __( 'PHP code hidden inside a media or font file.', 'index-sentinel' ) );
				}
			}
			if ( '.' === $name[0] && preg_match( '/\.php$/i', $name ) ) {
				$this->add( 'critical', 'hidden-php', $abs, __( 'Hidden PHP file (name starts with a dot).', 'index-sentinel' ) );
			}
			$parts = explode( '/', wp_normalize_path( dirname( $abs ) ) );
			$n     = count( $parts );
			if ( $n > 2 && $parts[ $n - 1 ] === $parts[ $n - 2 ] && preg_match( '/\.php$/i', $name )
				&& 0 !== strpos( wp_normalize_path( $abs ), wp_normalize_path( WP_PLUGIN_DIR ) ) ) {
				$this->add( 'warning', 'nested-folder', $abs, __( 'PHP file in a folder nested inside a folder of the same name, a pattern used by spam hacks.', 'index-sentinel' ) );
			}
		}
	}

	/**
	 * Database checks.
	 */
	private function database() {
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$posts = $wpdb->get_results(
			"SELECT ID, post_title, post_type FROM {$wpdb->posts}
			WHERE post_status IN ('publish','future','draft','private') AND post_type NOT IN ('revision','attachment')
			AND ( post_content LIKE '%<script%src=%' OR post_content LIKE '%<iframe%display:none%' OR post_content REGEXP 'ev[a]l\\\\(' OR post_content REGEXP 'document\\\\.write\\\\(unescape' )
			LIMIT 50"
		);
		foreach ( (array) $posts as $p ) {
			/* translators: 1: post title, 2: post type. */
			$this->add( 'warning', 'db-script', 'post #' . $p->ID, sprintf( __( '"%1$s" (%2$s) contains an external script or hidden iframe. Check that it is yours.', 'index-sentinel' ), $p->post_title, $p->post_type ) );
		}
		$cjk = $wpdb->get_results( "SELECT ID, post_title FROM {$wpdb->posts} WHERE post_status = 'publish' AND post_type <> 'revision' AND post_content REGEXP '[ぁ-んァ-ン]' LIMIT 20" );
		if ( ! in_array( get_locale(), array( 'ja', 'ja_JP' ), true ) ) {
			foreach ( (array) $cjk as $p ) {
				/* translators: %s: post title. */
				$this->add( 'critical', 'db-spam', 'post #' . $p->ID, sprintf( __( '"%s" contains Japanese text, a common sign of SEO spam injection.', 'index-sentinel' ), $p->post_title ) );
			}
		}
		$opts = $wpdb->get_results(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name NOT LIKE '%transient%' AND option_name NOT LIKE 'index\_sentinel\_%'
			AND ( option_value REGEXP 'ev[a]l\\\\(bas[e]64_decode' OR option_value REGEXP 'gzinf[l]ate\\\\(bas[e]64' OR option_value LIKE '%<script src=\"http%' ) LIMIT 20"
		);
		// phpcs:enable
		foreach ( (array) $opts as $o ) {
			$this->add( 'critical', 'db-option', 'option ' . $o->option_name, __( 'Option contains encoded PHP or an external script.', 'index-sentinel' ) );
		}
		$admins = wp_list_pluck( get_users( array( 'role' => 'administrator', 'fields' => array( 'user_login' ) ) ), 'user_login' );
		$known  = Store::get( 'admins', array() );
		if ( $known ) {
			foreach ( array_diff( $admins, $known ) as $login ) {
				$this->add( 'critical', 'new-admin', 'user ' . $login, __( 'Administrator account that did not exist at the last scan.', 'index-sentinel' ) );
			}
		}
		Store::set( 'admins', $admins );
	}

	/**
	 * Cloaking test: hacked sites often show spam only to Googlebot.
	 *
	 * @return array
	 */
	public function cloaking_check() {
		$args = array(
			'timeout'     => 20,
			'redirection' => 3,
			'user-agent'  => 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
			'headers'     => array( 'Cache-Control' => 'no-cache' ),
		);
		$home = wp_remote_get( add_query_arg( 'index_sentinel', time(), home_url( '/' ) ), $args );
		if ( is_wp_error( $home ) ) {
			return array( 'time' => time(), 'problems' => array(), 'note' => $home->get_error_message() );
		}
		$body     = (string) wp_remote_retrieve_body( $home );
		$problems = array();
		if ( ! in_array( get_locale(), array( 'ja', 'ja_JP' ), true ) && preg_match_all( '/[ぁ-んァ-ン]/u', $body ) > 20 ) {
			$problems[] = __( 'The homepage shown to Googlebot contains Japanese text.', 'index-sentinel' );
		}
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		preg_match_all( '#<a[^>]+href=["\']https?://([^/"\']+)#i', $body, $m );
		$external = array_filter(
			array_unique( $m[1] ),
			static function ( $h ) use ( $host ) {
				return false === strpos( $h, (string) $host );
			}
		);
		if ( count( $external ) > 60 ) {
			/* translators: %d: number of external sites. */
			$problems[] = sprintf( __( 'The homepage shown to Googlebot links to %d external sites.', 'index-sentinel' ), count( $external ) );
		}
		if ( preg_match( '#<div[^>]+style=["\'][^"\']*(display:\s*none|left:\s*-\d{3,}px)[^"\']*["\'][^>]*>\s*(<a\s|[^<]{0,40}<a\s)#i', $body ) ) {
			$problems[] = __( 'Hidden links found in the homepage HTML.', 'index-sentinel' );
		}
		$spam_code = 0;
		if ( Settings::spam_patterns() ) {
			$probe     = home_url( '/genus/proceeds/' . strtolower( wp_generate_password( 12, false ) ) . '.html' );
			$spam_code = (int) wp_remote_retrieve_response_code( wp_remote_get( $probe, $args ) );
			if ( $spam_code && ! in_array( $spam_code, array( 404, 410 ), true ) ) {
				/* translators: %d: HTTP status code. */
				$problems[] = sprintf( __( 'A spam-style URL answered HTTP %d to Googlebot instead of 410 or 404.', 'index-sentinel' ), $spam_code );
			}
		}
		return array(
			'time'      => time(),
			'problems'  => $problems,
			'home_code' => (int) wp_remote_retrieve_response_code( $home ),
			'spam_code' => $spam_code,
			'external'  => count( $external ),
		);
	}

	/**
	 * Move a reported file into a locked quarantine folder.
	 *
	 * @param string $rel Path relative to ABSPATH.
	 * @return bool
	 */
	public static function quarantine( $rel ) {
		$abs = realpath( ABSPATH . ltrim( $rel, '/' ) );
		if ( ! $abs || 0 !== strpos( wp_normalize_path( $abs ), wp_normalize_path( ABSPATH ) ) || ! is_file( $abs ) || 'wp-config.php' === basename( $abs ) ) {
			return false;
		}
		$q = WP_CONTENT_DIR . '/index-sentinel-quarantine';
		if ( ! is_dir( $q ) ) {
			wp_mkdir_p( $q );
			file_put_contents( $q . '/.htaccess', "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			file_put_contents( $q . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}
		$dest = $q . '/' . gmdate( 'Ymd-His' ) . '-' . str_replace( '/', '__', $rel ) . '.quarantined';
		if ( ! @rename( $abs, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
			return false;
		}
		$list          = Store::get( 'quarantine', array() );
		$list[ $dest ] = array( 'from' => $rel, 'time' => time() );
		Store::set( 'quarantine', $list );
		/* translators: %s: file path. */
		Store::log( 'quarantine', sprintf( __( 'Quarantined %s', 'index-sentinel' ), $rel ), 'warning' );
		return true;
	}

	/**
	 * Restore a quarantined file.
	 *
	 * @param string $dest Quarantine path.
	 * @return bool
	 */
	public static function restore( $dest ) {
		$list = Store::get( 'quarantine', array() );
		if ( ! isset( $list[ $dest ] ) || ! is_file( $dest ) ) {
			return false;
		}
		$from = $list[ $dest ]['from'];
		$to   = ABSPATH . $from;
		if ( file_exists( $to ) || ! @rename( $dest, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
			return false;
		}
		unset( $list[ $dest ] );
		Store::set( 'quarantine', $list );
		/* translators: %s: file path. */
		Store::log( 'quarantine', sprintf( __( 'Restored %s', 'index-sentinel' ), $from ), 'info' );
		return true;
	}

	/**
	 * Recursive file list.
	 *
	 * @param string   $dir  Folder.
	 * @param string[] $skip Folder names to skip.
	 * @return \Generator
	 */
	private function walk( $dir, $skip = array() ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$it = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
				static function ( $f ) use ( $skip ) {
					return ! $f->isLink() && ! ( $f->isDir() && in_array( $f->getFilename(), $skip, true ) );
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $file ) {
			if ( $file->isFile() ) {
				yield $file->getPathname();
			}
		}
	}
}
