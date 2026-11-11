function cleanup() {
	$.get('SpoofCookie/cleanup', function() {
		document.querySelectorAll('.spoof-auth-active').forEach(function(marker) { marker.remove(); });
		$('#spoof_username').removeAttr('disabled');
		$('#spoof_password').removeAttr('disabled');
		$('#spoof_submit').removeAttr('disabled');
		$('#spoof_attack_feedback').html('');
		$('#spoof_attack_output').html('');
	});
}

var target = document.getElementById('spoof_attack_feedback').parentElement;

var obs = new MutationObserver(function(mutations) {
	mutations.forEach(function() {
		if (document.querySelector('.spoof-auth-active')) {
			$('#spoof_username').prop('disabled', true);
			$('#spoof_password').prop('disabled', true);
			$('#spoof_submit').prop('disabled', true);
		}
	});
});

obs.observe(target, { characterData: false, attributes: false, childList: true, subtree: true });
