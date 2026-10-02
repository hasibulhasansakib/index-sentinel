<?php
/**
 * Google Search Console data through Site Kit.
 *
 * @package IndexSentinel
 */

namespace IndexSentinel\Modules;

use IndexSentinel\Settings;
use IndexSentinel\Store;

defined( 'ABSPATH' ) || exit;

/**
 * Uses the Google connection that Site Kit by Google already has (no extra login or API key):
 * - sitemap status,
 * - URL Inspection for every URL in your sitemaps (indexed or not, last crawl),
 * - every page that got impressions in the last 28 days, sorted into: your pages / known spam / UNKNOWN.
 *   An unknown URL with impressions is usually the first sign of a new spam injection.
 *
 * Optional: without Site Kit (or without the Search Console module) this module simply stays off.
 */
final class Google {

	/**
	 * Is Site Kit connected to Search Console?
	 *
	 * @return bool
	 */
	public static function available() {
		$settings = get_option( 'googlesitekit_search-console_settings' );
		return defined( 'GOOGLESITEKIT_PLUGIN_MAIN_FILE' )
			&& class_exists( '\Google\Site_Kit\Modules\Search_Console' )
			&& class_exists( '\Google\Site_Kit\Context' )
			&& is_array( $settings ) && ! empty( $settings['propertyID'] );
	}

	/**
	 * Search Console service object and property.
	 *
	 * @return array [service, property, owner user id]
	 */
	private function service() {
		$settings = get_option( 'googlesitekit_search-console_settings' );
		$owner    = ! empty( $settings['ownerID'] ) ? (int) $settings['ownerID'] : 0;
		if ( ! $owner ) {
			$admins = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
			$owner  = $admins ? (int) $admins[0] : 0;
		}
		$module  = new \Google\Site_Kit\Modules\Search_Console( new \Google\Site_Kit\Context( GOOGLESITEKIT_PLUGIN_MAIN_FILE ) );
		$service = new \Google\Site_Kit_Dependencies\Google\Service\SearchConsole( $module->get_client() );
		return array( $service, $settings['propertyID'], $owner );
	}

	/**
	 * URLs listed in the site's sitemaps (core wp-sitemap.xml or SEO plugin sitemap_index.xml).
	 *
	 * @return string[]
	 */
	public function sitemap_urls() {
		$urls = array();
		foreach ( array( '/sitemap_index.xml', '/wp-sitemap.xml', '/sitemap.xml' ) as $index ) {
			$res = wp_remote_get( home_url( $index ), array( 'timeout' => 20 ) );
			if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
				continue;
			}
			$body = wp_remote_retrieve_body( $res );
			preg_match_all( '#<loc>([^<]+)</loc>#', $body, $locs );
			$maps = false !== strpos( $body, '<sitemapindex' ) ? $locs[1] : array();
			if ( ! $maps ) {
				$urls = $locs[1];
			}
			foreach ( $maps as $map ) {
				$sub = wp_remote_retrieve_body( wp_remote_get( html_entity_decode( $map ), array( 'timeout' => 20 ) ) );
				preg_match_all( '#<loc>([^<]+)</loc>#', $sub, $m );
				$urls = array_merge( $urls, $m[1] );
			}
			break;
		}
		$urls = array_filter(
			array_map( 'html_entity_decode', $urls ),
			static function ( $u ) {
				return ! preg_match( '#\.(jpe?g|png|webp|gif|xml)$#i', $u );
			}
		);
		return array_values( array_unique( $urls ) );
	}

	/**
	 * Refresh everything from Google.
	 *
	 * @param int $inspect_limit URL Inspection calls in this run (the oldest-checked URLs go first).
	 * @return array
	 */
	public function refresh( $inspect_limit = 60 ) {
		$data = Store::get( 'google', array() );
		if ( ! self::available() ) {
			$data['error'] = __( 'Site Kit by Google is not installed or not connected to Search Console.', 'index-sentinel' );
			Store::set( 'google', $data );
			return $data;
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$prev = get_current_user_id();
		try {
			list( $svc, $property, $owner ) = $this->service();
			wp_set_current_user( $owner );

			$data['sitemaps'] = array();
			foreach ( (array) $svc->sitemaps->listSitemaps( $property )->getSitemap() as $s ) {
				$data['sitemaps'][] = array(
					'path'       => $s->getPath(),
					'downloaded' => $s->getLastDownloaded(),
					'errors'     => (int) $s->getErrors(),
					'warnings'   => (int) $s->getWarnings(),
					'pending'    => (bool) $s->getIsPending(),
				);
			}

			$urls  = $this->sitemap_urls();
			$known = isset( $data['urls'] ) ? array_intersect_key( (array) $data['urls'], array_flip( $urls ) ) : array();
			usort(
				$urls,
				static function ( $a, $b ) use ( $known ) {
					return ( isset( $known[ $a ]['checked'] ) ? $known[ $a ]['checked'] : 0 ) <=> ( isset( $known[ $b ]['checked'] ) ? $known[ $b ]['checked'] : 0 );
				}
			);
			foreach ( array_slice( $urls, 0, max( 0, (int) $inspect_limit ) ) as $url ) {
				$req = new \Google\Site_Kit_Dependencies\Google\Service\SearchConsole\InspectUrlIndexRequest();
				$req->setInspectionUrl( $url );
				$req->setSiteUrl( $property );
				$r             = $svc->urlInspection_index->inspect( $req )->getInspectionResult()->getIndexStatusResult();
				$known[ $url ] = array(
					'verdict'  => $r->getVerdict(),
					'coverage' => $r->getCoverageState(),
					'crawl'    => $r->getLastCrawlTime(),
					'checked'  => time(),
				);
			}
			foreach ( $urls as $u ) {
				if ( ! isset( $known[ $u ] ) ) {
					$known[ $u ] = array( 'verdict' => 'PENDING', 'coverage' => __( 'Not checked yet', 'index-sentinel' ), 'crawl' => '', 'checked' => 0 );
				}
			}
			$data['urls'] = $known;

			$req = new \Google\Site_Kit_Dependencies\Google\Service\SearchConsole\SearchAnalyticsQueryRequest();
			$req->setStartDate( gmdate( 'Y-m-d', strtotime( '-28 days' ) ) );
			$req->setEndDate( gmdate( 'Y-m-d' ) );
			$req->setDimensions( array( 'page' ) );
			$req->setRowLimit( 5000 );
			$rows    = (array) $svc->searchanalytics->query( $property, $req )->getRows();
			$own     = array_flip( $urls );
			$real    = array();
			$spam    = array();
			$unknown = array();
			$totals  = array( 'real' => array( 0, 0 ), 'spam' => array( 0, 0 ), 'unknown' => array( 0, 0 ) );
			foreach ( $rows as $row ) {
				$keys = $row->getKeys();
				$u    = $keys[0];
				$item = array( 'url' => $u, 'clicks' => (int) $row->getClicks(), 'impressions' => (int) $row->getImpressions(), 'position' => round( (float) $row->getPosition(), 1 ) );
				$path = (string) wp_parse_url( $u, PHP_URL_PATH );
				if ( isset( $own[ $u ] ) || $this->is_own_url( $u ) ) {
					$bucket = 'real';
					$real[] = $item;
				} elseif ( Settings::is_spam_path( $path ) ) {
					$bucket = 'spam';
					$spam[] = $item;
				} else {
					$bucket    = 'unknown';
					$unknown[] = $item;
				}
				$totals[ $bucket ][0] += $item['clicks'];
				$totals[ $bucket ][1] += $item['impressions'];
			}
			$hist                         = isset( $data['spam_history'] ) ? (array) $data['spam_history'] : array();
			$hist[ gmdate( 'Y-m-d' ) ]    = array( 'spam_pages' => count( $spam ), 'spam_impr' => $totals['spam'][1], 'real_impr' => $totals['real'][1] );
			$data['spam_history']         = array_slice( $hist, -60, null, true );
			$data['analytics']            = array(
				'real'        => array_slice( $real, 0, 50 ),
				'spam_count'  => count( $spam ),
				'spam_sample' => array_slice( $spam, 0, 15 ),
				'unknown'     => array_slice( $unknown, 0, 50 ),
				'totals'      => $totals,
			);
			$data['updated']              = time();
			unset( $data['error'] );
		} catch ( \Throwable $e ) {
			/* translators: %s: error message from Google. */
			$data['error'] = sprintf( __( 'Google API error: %s', 'index-sentinel' ), $e->getMessage() );
		}
		wp_set_current_user( $prev );
		Store::set( 'google', $data );
		return $data;
	}

	/**
	 * URLs that belong to the site even if they are not in a sitemap (the homepage variants, an existing post or page).
	 *
	 * @param string $url URL.
	 * @return bool
	 */
	private function is_own_url( $url ) {
		$path = trim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
		if ( '' === $path ) {
			return true;
		}
		return (bool) url_to_postid( $url );
	}
}
