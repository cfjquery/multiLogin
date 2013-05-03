<cfswitch expression="#application.current_login_method#">
	<cfcase value="twitter">
	</cfcase>
	<cfcase value="facebook">
		<cfhttp url="https://graph.facebook.com/me?access_token=#application.facebook_access_token#" result="userInfo">
	</cfcase>
	<cfcase value="linkedin">
		<!--- Get the USERINFO --->
		<cfhttp url="https://api.linkedin.com/v1/people/~?oauth2_access_token=#application.linkedin_access_token#" result="userInfo">
			<cfhttpparam type="header" name="x-li-format" value="json">
		</cfhttp>
	</cfcase>
	<cfcase value="google">
		<!--- Get the USERINFO --->
		<cfhttp url="https://www.googleapis.com/oauth2/v1/userinfo" result="userInfo" method="get" resolveurl="true">
			<cfhttpparam type="header" name="Authorization" value="OAuth #application.google_access_token#">
			<cfhttpparam type="header" name="GData-Version" value="3">
		</cfhttp>
	</cfcase>
</cfswitch>
<cfif application.current_login_method neq 'twitter'>
	<cfif isJSON(userInfo.filecontent)>
		<cfset data = deserializeJSON(userInfo.filecontent)>
		<cfdump var="#data#">
	<cfelse>
		ERROR
		<cfdump var="#userInfo.filecontent#">
	</cfif>
</cfif>


