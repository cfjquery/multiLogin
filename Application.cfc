<cfcomponent displayname="Application" output="true" hint="Handle the application.">
    <cfscript>
        this.Name               = "mutliLogin";
        this.ApplicationTimeout = CreateTimeSpan( 0, 0, 1, 0 );
        this.SessionManagement  = true;
        this.SetClientCookies   = true;
        this.mappings['/cfc']   = GetDirectoryFromPath(GetCurrentTemplatePath()) & "/cfc";
        this.TargetPage = 'index.cfm';
    </cfscript> 
    <cfsetting requesttimeout="20" showdebugoutput="true" enablecfoutputonly="false" />
    <cffunction name="OnApplicationStart" access="public" returntype="boolean" output="false" hint="Fires when application created.">
        <cfscript>
            //USED FOR TRACKING WHICH METHOD IS BEING USED TO LOGIN
            application.current_login_method = '';
            //USED FOR ALL INITIAL LOGIN CALLS
            application.login_state = '';
            //USED TO HOLD THE CURRENT ACCESS TOKEN
            application.current_access_token = '';
            //USED FOR ALL REDIRECTS BACK TO LOCAL PAGE
            application.redirect_uri = "http://localhost/multiLogin/processLogin.cfm";
            //TWITTER
            applicaton.twitter_access_token = '';
            application.twitter_access_token_secret = '';
            application.twitter_consumer_key = 'YOUR APP VALUES HERE';
            application.twitter_consumer_secret = 'YOUR APP VALUES HERE';
            application.twitter_redirecturl = "http://localhost/multiLogin/processLogin.cfm";
            //FACEBOOK
            application.facebook_access_token = '';
            application.facebook_code = "";
            application.facebook_appid = "YOUR APP VALUES HERE";
            application.facebook_secret = "YOUR APP VALUES HERE";
            application.facebook_baseurl = "https://www.facebook.com/dialog/oauth";
            application.facebook_redirecturl = "http://localhost/multiLogin/processLogin.cfm";
            //LINKEDIN
            application.linkedin_access_token = "";
            application.linkedin_code = "";
            application.linkedin_apikey = "YOUR APP VALUES HERE";
            application.linkedin_secretkey = "YOUR APP VALUES HERE";
            application.linkedin_baseurl = "https://www.linkedin.com/uas/oauth2/authorization";
            application.linkedin_redirecturl = "http://localhost/multiLogin/processLogin.cfm";
            //GOOGLE
            application.google_access_token = "";
            application.google_code = "";
            application.google_client_id = "";
            application.google_apikey = "YOUR APP VALUES HERE";
            application.google_secretkey = "YOUR APP VALUES HERE";
            application.google_baseurl = "https://accounts.google.com/o/oauth2/auth";
            application.google_redirecturl = "http://localhost/multiLogin/processLogin.cfm";
            return true;
        </cfscript>
    </cffunction>   
    <cffunction name="onrequestStart">
        <cfscript>
        if(structKeyExists(url, 'reinit')) {
            onApplicationStart();
        }
        </cfscript>
    </cffunction>
    <cffunction name="OnError" access="public" returntype="void" output="true" hint="Fires when exception occurs not caught by try/catch.">
        <cfargument name="Exception" type="any" required="true" />
        <cfargument name="EventName" type="string" required="false" default="" />
        <cfsavecontent variable="theError">
            #now()#
            <cfdump var="#arguments.Exception#" />
        </cfsavecontent>
        <cffile action="write" file="C:\Program Files (x86)\Apache Software Foundation\Apache2.2\htdocs\multiLogin\err.html" output="#theError#">
        <cfreturn />
    </cffunction>
</cfcomponent>
