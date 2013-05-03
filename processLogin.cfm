<cfset objLogin = CreateObject("component", "cfc.login")>

<!--- INITIALISE LOGIN BY TYPE --->
<cfif IsDefined("url.loginType")>
	<cfswitch expression="#url.loginType#">
		<cfcase value="twitter">
			<cfset application.current_login_method = 'twitter'>
			<cfset twitterLogin = objLogin.get_request_token()>
		</cfcase>
		<cfcase value="facebook">
			<cfset application.current_login_method = 'facebook'>
			<cfset facebookLogin = objLogin.initiate_login(
				loginUrlBase = "https://www.facebook.com/dialog/oauth",
				loginClientID = application.facebook_appid,
				loginRedirectURI = application.facebook_redirecturl,
				loginScope = "friends_hometown"
			)>
		</cfcase>
		<cfcase value="linkedin">
			<cfset application.current_login_method = 'linkedin'>
			<cfset linkedinLogin = objLogin.initiate_login(
				loginUrlBase = "https://www.linkedin.com/uas/oauth2/authorization",
				loginClientID = application.linkedin_apikey,
				loginRedirectURI = application.linkedin_redirecturl,
				loginScope = "r_basicprofile%20r_network%20w_messages"
			)>
		</cfcase>
		<cfcase value="google">
			<cfset application.current_login_method = 'google'>
			<cfset googleLogin = objLogin.initiate_login(
				loginUrlBase = "https://accounts.google.com/o/oauth2/auth",
				loginClientID = application.google_client_id,
				loginRedirectURI = application.google_redirecturl,
				loginScope = "https://www.googleapis.com/auth/userinfo.profile"
			)>
		</cfcase>
	</cfswitch>
</cfif>

<!--- TWITTER CALLBACK --->
<cfif application.current_login_method is 'twitter'>
	<cfif isDefined("url.returnFromTwitter")>
		<cfscript>
			// Get the access token for this user and store it for future use
			getAccessToken = objLogin.get_access_token();
			// Get the basics user details so that we have a screen_name we can use
			getTwitterDetails = objLogin.get_twitter_details();
			twitterData = DeserializeJSON(getTwitterDetails);
			session.twitter_screen_name = twitterData.screen_name;
			// Build the twitter4j stuff
			configBuilder = createObject("java", "twitter4j.conf.ConfigurationBuilder");
			configBuilder.setOAuthConsumerKey(#application.twitter_consumer_key#);
			configBuilder.setOAuthConsumerSecret(#application.twitter_consumer_secret#);
			configBuilder.setOAuthAccessToken(#application.twitter_access_token#);
			configBuilder.setOAuthAccessTokenSecret(#application.twitter_access_token_secret#);
			config = configBuilder.build();
			twitterFactory = createObject("java", "twitter4j.TwitterFactory").init(config);
			twitter = twitterFactory.getInstance();
			// Now we can get the User ID, Real Name, User Image etc...
			getUserDetails = twitter.showUser("#session.twitter_screen_name#");
		</cfscript>
		<cfoutput>#getUserDetails#</cfoutput>
	</cfif>
</cfif>
<!--- FACEBOOK CALLBACK --->
<cfif application.current_login_method is 'facebook'>
	<cfif isDefined("url.code") and url.state is application.login_state>
		<cfset application.facebook_code = url.code>
		<!--- Get the ACCESS TOKEN --->
		<cfset facebookAuthorise = objLogin.authorise_login(
			authUrlBase = "https://graph.facebook.com/oauth/access_token",
			authRedirectURI = application.redirect_uri,
			authMethod = "post",
			authCode = application.facebook_code,
			authClientId = application.facebook_appid,
			authClientSecret = application.facebook_secret,
			authGrantType = "authorization_code"
		)>
		<cfif findNoCase("access_token=", facebookAuthorise.filecontent)>
	        <!--- Set the ACCESS TOKEN --->
			<cfset part1 = listGetAt(facebookAuthorise.filecontent, 1, "&")>
			<cfset application.facebook_access_token = listGetAt(part1, 2, "=")>
			<cfinclude template="displayInfo.cfm">
 		<cfelse>
			ERROR
			<cfdump var="#facebookAuthorise.filecontent#">
		</cfif>
 	</cfif>
</cfif>
<!--- LINKEDIN CALLBACK --->
<cfif application.current_login_method is 'linkedin'>
	<cfif isDefined("url.code") and url.state is application.login_state>
		<cfset application.linkedin_code = url.code>
		<!--- Get the ACCESS TOKEN --->
		<cfset linkedinAuthorise = objLogin.authorise_login(
			authUrlBase = "https://www.linkedin.com/uas/oauth2/accessToken",
			authRedirectURI = application.redirect_uri,
			authMethod = "post",
			authCode = application.linkedin_code,
			authClientId = application.linkedin_apikey,
			authClientSecret = application.linkedin_secretkey,
			authGrantType = "authorization_code"
		)>
        <cfif isJSON(linkedinAuthorise.filecontent)>
	        <!--- Set the ACCESS TOKEN --->
            <cfset result = deserializeJSON(linkedinAuthorise.filecontent)>
			<cfset application.linkedin_access_token = result.access_token>
			<cfinclude template="displayInfo.cfm">
 		<cfelse>
			ERROR
			<cfdump var="#linkedinAuthorise.filecontent#">
		</cfif>
	</cfif>
</cfif>
<!--- GOOGLE CALLBACK --->
<cfif application.current_login_method is 'google'>
	<cfif isDefined("url.code") and url.state is application.login_state>
		<cfset application.google_code = url.code>
		<!--- Get the ACCESS TOKEN --->
		<cfset googleAuthorise = objLogin.authorise_login(
			authUrlBase = "https://accounts.google.com/o/oauth2/token",
			authRedirectURI = application.redirect_uri,
			authMethod = "post",
			authCode = application.google_code,
			authClientId = application.google_client_id,
			authClientSecret = application.google_secretkey,
			authGrantType = "authorization_code"
		)>
        <cfif isJSON(googleAuthorise.filecontent)>
	        <!--- Set the ACCESS TOKEN --->
            <cfset result = deserializeJSON(googleAuthorise.filecontent)>
			<cfset application.google_access_token = result.access_token>
			<cfinclude template="displayInfo.cfm">
 		<cfelse>
			ERROR
			<cfdump var="#googleAuthorise.filecontent#">
		</cfif>
	</cfif>
</cfif>
