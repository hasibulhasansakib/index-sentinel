/**
 * Index Sentinel admin: run long jobs over AJAX with a busy state, confirm risky actions.
 *
 * @package IndexSentinel
 */
( function () {
	'use strict';

	var settings = window.IndexSentinel || {};
	var i18n = settings.i18n || {};
	var toast = document.getElementById( 'idxs-toast' );

	function show( text, bad ) {
		if ( ! toast ) {
			return;
		}
		toast.textContent = text;
		toast.classList.toggle( 'is-bad', !! bad );
		toast.hidden = false;
	}

	function setBusy( task, busy ) {
		document.querySelectorAll( '[data-idxs-run="' + task + '"]' ).forEach( function ( b ) {
			b.classList.toggle( 'is-busy', busy );
			b.disabled = busy;
		} );
	}

	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest( '[data-idxs-run]' );
		if ( ! btn || btn.classList.contains( 'is-busy' ) ) {
			return;
		}
		var task = btn.getAttribute( 'data-idxs-run' );
		setBusy( task, true );
		show( 'scan' === task ? i18n.scanning : i18n.working );

		var body = new URLSearchParams();
		body.append( 'action', 'index_sentinel_run' );
		body.append( 'task', task );
		body.append( 'nonce', settings.nonce );

		fetch( settings.ajax, { method: 'POST', body: body, credentials: 'same-origin' } )
			.then( function ( res ) {
				return res.json();
			} )
			.then( function ( json ) {
				show( json.data || i18n.done, ! json.success );
				if ( json.success ) {
					window.setTimeout( function () {
						window.location.reload();
					}, 900 );
				} else {
					setBusy( task, false );
				}
			} )
			.catch( function () {
				show( i18n.failed, true );
				setBusy( task, false );
			} );
	} );

	document.addEventListener( 'submit', function ( e ) {
		var form = e.target.closest( 'form[data-idxs-confirm]' );
		if ( form && ! window.confirm( form.getAttribute( 'data-idxs-confirm' ) ) ) {
			e.preventDefault();
		}
	} );
} )();
