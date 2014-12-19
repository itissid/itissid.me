var app = app || {};

(function () {
	'use strict';

	// UserInfo Model
	// ---------
	var UserInfo = Backbone.Model.extend({
		defaults: {
			name: '',
			email: '',
			picture: '',
			link: ''
		}
	});
	app.userInfo = new UserInfo();
})();
