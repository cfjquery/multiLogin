<cfcomponent displayname="Login">
    <!--- ************************************************************ --->
    <!--- HMAC-SHA1 AUTHENTICATION CODE FUNCTION                       --->
    <!---                                                              --->
    <!---   Contrary to ColdFusion's docs, the Encrypt() and Hash()    --->
    <!---   functions do not support HMAC-SHA1 as required by this     --->
    <!---   project.  This function, provided by Dmitry Yakhnov of     --->
    <!---   Yakhnov Studio (http://www.coldfusiondeveloper.com.au/)    --->
    <!---   takes advantage of Java's native support for HMAC-SHA1.    --->
    <!---   Thank you for sharing, Dmitry!                             --->
    <!---                                                              --->
    <!--- PARAMETERS                                                   --->
    <!---   signKey (string) = Secret key                              --->
    <!---   signMessage (string) = Message to be hashed                --->
    <!---                                                              --->
    <!--- RETURNS                                                      --->
    <!---   (binary) The keyed authentication code                     --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="HMAC_SHA1" returntype="binary" access="remote" output="no">
       <cfargument name="signKey" type="string" required="true" />
       <cfargument name="signMessage" type="string" required="true" />
       <cfset var jMsg = JavaCast("string",arguments.signMessage).getBytes("iso-8859-1") />
       <cfset var jKey = JavaCast("string",arguments.signKey).getBytes("iso-8859-1") />
       <cfset var key = createObject("java","javax.crypto.spec.SecretKeySpec") />
       <cfset var mac = createObject("java","javax.crypto.Mac") />
       <cfset key = key.init(jKey,"HmacSHA1") />
       <cfset mac = mac.getInstance(key.getAlgorithm()) />
       <cfset mac.init(key) />
       <cfset mac.update(jMsg) />
       <cfreturn mac.doFinal() />
    </cffunction>
    <!--- ************************************************************ --->
    <!--- OAUTH SIGNATURE BASE STRING FUNCTION                         --->
    <!---                                                              --->
    <!---   In accordance with the OAuth specification, this function  --->
    <!---   takes three input values (http method, base uri, and a     --->
    <!---   list, er, 'structure' of "key = value" parameters) and     --->
    <!---   returns a single OAuth base string.                        --->
    <!---                                                              --->
    <!--- AUTHOR                                                       --->
    <!---   Dave Delbridge, Circa 3000 (http://circa3000.com)          --->
    <!---                                                              --->
    <!--- PARAMETERS                                                   --->
    <!---   HTTP_METHOD (string) = "GET" or "POST"                     --->
    <!---   BASE_URI (string) = address where request will be sent,    --->
    <!---     minus any URL request parameters                         --->
    <!---   PARAMETERS (structure) = key/value parameter pairs         --->
    <!---     Example:                                                 --->
    <!---       params[oauth_nonce] = 12345                            --->
    <!---       params[oauth_version] = "1.0"                          --->
    <!---                                                              --->
    <!--- RETURNS                                                      --->
    <!---   (string) The sorted, URL-encoded, concatenated values      --->
    <!---     (the "signature base string") per OAuth spec             --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="OauthBaseString" returntype="string" access="remote" output="no">
        <!--- Required parameters (http_method, base_uri, values) --->
        <cfargument name="http_method" type="string" required="true">
        <cfargument name="base_uri" type="string" required="true">
        <cfargument name="parameters" type="struct" required="true">
        <!--- Concatenate http_method & URL-encoded base_uri --->
        <cfset oauth_signature_base_string = http_method & "&" & URLEncodedFormat_3986(base_uri) & "&">
        <!--- Create sorted list of parameter keys --->
        <cfset keys_list = StructKeyList(parameters)>
        <cfset keys_list_sorted = ListSort(keys_list,"textnocase")>
        <cfset amp = "">    <!--- first iteration requires no ampersand --->
        <!--- Repeat for each parameter --->
        <cfloop list="#keys_list_sorted#" index="key">
            <!--- Concatenate URL-encoded parameter (key/value pair) --->
            <cfset oauth_signature_base_string = oauth_signature_base_string & URLEncodedFormat_3986(amp & LCase(key) & "=" & parameters[key])>
            <cfset amp = "&">   <!--- successive iterations require a starting ampersand --->
        </cfloop>
        <!--- Return with OAuth signature base string --->
        <cfreturn oauth_signature_base_string>
    </cffunction>
    <!--- ************************************************************ --->
    <!--- OAUTH REQUEST FUNCTION                                       --->
    <!---                                                              --->
    <!---   Per OAuth specification, sends specified request and       --->
    <!---   parameters to the specified provider (e.g., Twitter).      --->
    <!---   Response is returned in a string.                          --->
    <!---                                                              --->
    <!--- AUTHOR                                                       --->
    <!---   Dave Delbridge, Circa 3000 (http://circa3000.com)          --->
    <!---                                                              --->
    <!--- PARAMETERS                                                   --->
    <!---   HTTP_METHOD (string) = "GET" or "POST"                     --->
    <!---   REQUEST_URL (string) = unencoded address where request is  --->
    <!---     to be sent, including any URL request parameters.  All   --->
    <!---     ampersand (&) and equals (=) symbols appearing in any    --->
    <!---     URL request parameter values must be escaped (e.g.,      --->
    <!---     "&&", "==").                                             --->
    <!---   OAUTH_CONSUMER_SECRET (string) = consumer secret provided  --->
    <!---     by provider (e.g., Twitter)                              --->
    <!---   PARAMS = structure containing request parameters           --->
    <!---     Example:                                                 --->
    <!---       params[oauth_nonce] = 12345                            --->
    <!---       params[oauth_version] = "1.0"                          --->
    <!---                                                              --->
    <!--- RETURNS                                                      --->
    <!---   (string) The provider's response                           --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="oauth_request" returntype="string" access="remote" output="no">
        <!--- Parameters --->
        <cfargument name="consumer_secret" type="string" required="yes">
        <cfargument name="token_secret" type="string" required="yes">
        <cfargument name="http_method" type="string" required="yes">
        <cfargument name="request_url" type="string" required="yes">
        <cfargument name="params" type="struct" required="yes">
        <!--- Backup parameters for later --->
        <cfset params_backup = Duplicate(params)>
        <!--- Copy URL variables (if any) to parameters --->
        <!--- Parse address and parameters from request URL --->
        <cfset request_url_address = request_url>
        <cfset request_url_query_string = "">
        <cfset question_mark = Find("?",request_url,1)>
        <cfif question_mark neq 0>
            <cfset request_url_address = Left(request_url,question_mark-1)>
            <cfset request_url_query_string = Right(request_url,(len(request_url)-question_mark))>
            <!--- Repeat for each key/value pair                               --->
            <cfset request_url_query_string = Replace(request_url_query_string, "&&", "PLACEHOLDER_AMPERSAND", "ALL")>  <!--- save escaped ampersand (&) symbols --->
            <cfset request_url_query_string = Replace(request_url_query_string, "==", "PLACEHOLDER_EQUALS", "ALL")>  <!--- save escaped equals (=) symbols --->
            <cfset params_list = ListChangeDelims(request_url_query_string,",","&,=")>
            <cfloop from="1" to="#ListLen(params_list)#" index="index" step="2">
                <!--- Add parameter to Params structure                            --->
                <cfset params[ListGetAt(params_list,index)] = ListGetAt(params_list,index+1)>
                <cfset params[ListGetAt(params_list,index)] = Replace(params[ListGetAt(params_list,index)], "PLACEHOLDER_AMPERSAND", "&", "ALL")>   <!--- restore escaped ampersand (&) symbols as non-escaped --->
                <cfset params[ListGetAt(params_list,index)] = Replace(params[ListGetAt(params_list,index)], "PLACEHOLDER_EQUALS", "=", "ALL")>  <!--- restore escaped equals (=) symbols as non-escaped --->
            </cfloop>
        </cfif>
        <!--- Generate signature base string --->
        <!--- All parameters must be URL-encoded --->
        <cfloop list="#StructKeyList(params)#" index="key">
            <cfset params[key] = URLEncodedFormat_3986(params[key])>
        </cfloop>
        <!--- Get the base string --->
        <cfset signature_base_string = OauthBaseString(http_method,request_url_address,params)>
        <!--- Generate composite signing key --->
        <cfset composite_signing_key = consumer_secret & "&" & token_secret>
        <!--- Generate the SHA1 hash --->
        <cfset signature = ToBase64(HMAC_SHA1(composite_signing_key,signature_base_string))>
        <!--- Hash (now that we have it) must also be URL encoded --->
        <cfset signature = URLEncodedFormat_3986(signature)>
        <!--- Submit request to provider (e.g., Twitter) --->
        <!--- Generate header parameters string --->
        <cfset oauth_header = "OAuth ">
        <!--- Parameters (minus URL parameters) --->
        <cfset comma = "">
        <cfloop list="#StructKeyList(params_backup)#" index="key">  <!--- use backup list of parameter keys to remove query parameters --->
            <cfset oauth_header = oauth_header & comma & key & "=""" & params[key] & """">  <!--- ...but use current (URL-encoded) parameter values --->
            <cfset comma = ", ">
        </cfloop>
        <!--- Signature --->
        <cfset oauth_header = oauth_header & ", oauth_signature=""" & signature & """">
        <!--- Send request --->
        <cfhttp method="post" url="#request_url_address#">
            <!--- Header --->
            <cfhttpparam type="header" name="Authorization" value="#oauth_header#" encoded="no">
            <!--- Parameters --->
            <cfloop list="#StructKeyList(params)#" index="key">
                <cfif not StructKeyExists(params_backup,key)>   <!--- just the query parameters --->
                    <cfhttpparam type="formfield" name="#key#" value="#params[key]#" encoded="no">
                </cfif>
            </cfloop>
        </cfhttp>
        <cfif cfhttp.Statuscode neq "200 OK">
            <h1>Failure!</h1>
            <cfdump var="#variables#">
            <cfabort>
        </cfif>
        <cfreturn cfhttp.FileContent>
    </cffunction>
    <!--- ************************************************************ --->
    <!--- RFC 3986-COMPLIANT URLENCODEDFORMAT() FUNCTION               --->
    <!---                                                              --->
    <!---   Per "URL Encoding to RFC 3986" in Adobe's Developer        --->
    <!---   Connection, this function corrects inconsistencies in      --->
    <!---   ColdFusion's URLEncodedFormat() function that are known    --->
    <!---   to break OAuth authentication attempts.                    --->
    <!---                                                              --->
    <!--- AUTHOR                                                       --->
    <!---   Dave Delbridge, Circa 3000 (http://circa3000.com)          --->
    <!---                                                              --->
    <!--- PARAMETERS                                                   --->
    <!---   URL (string) = address to be url-encoded                   --->
    <!---                                                              --->
    <!--- RETURNS                                                      --->
    <!---   (string) Url-encoded address, per RFC 3986                 --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="URLEncodedFormat_3986" returntype="string" access="remote" output="no">
        <cfargument name="url" type="string" required="true" />
        <cfset rfc_3986_bad_chars = "%2D,%2E,%5F,%7E">
        <cfset rfc_3986_good_chars = "-,.,_,~">
        <cfset url = ReplaceList(URLEncodedFormat(url),rfc_3986_bad_chars,rfc_3986_good_chars)>
       <cfreturn url />
    </cffunction>
    <!--- ************************************************************ --->
    <!--- GET OAUTH REQUEST TOKEN                                      --->
    <!---                                                              --->
    <!---   Executes the first three steps of Twitter's OAuth dia-     --->
    <!---   gram - sends Consumer Key to Twitter (Step A), receives    --->
    <!---   a Request Token (Step B), and redirects the user to        --->
    <!---   Twitter for authentication (Step C).                       --->
    <!---                                                              --->
    <!---   Once authenticated, Twitter will return the user to us,    --->
    <!---   to the callback template specified here, in parameter      --->
    <!---   OAUTH_CALLBACK.  Our callback url employs CF session       --->
    <!---   tokens to preserve session state (with our new request     --->
    <!---   tokens); no cookies required.                              --->
    <!---                                                              --->
    <!--- AUTHOR                                                       --->
    <!---   Dave Delbridge, Circa 3000 (http://circa3000.com)          --->
    <!---                                                              --->
    <!--- INPUT                                                        --->
    <!---   n/a                                                        --->
    <!---                                                              --->
    <!--- OUTPUT                                                       --->
    <!---   SESSION.OAUTH_REQUEST_TOKEN = OAuth request token          --->
    <!---   SESSION.OAUTH_REQUEST_TOKEN_SECRET = OAuth request token   --->
    <!---     secret                                                   --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="get_request_token" returntype="none" access="remote" output="no">
        <!--- Variables --->
        <cfset gmt_time_zone = "8"> <!--- Greenwich mean time offset at server --->
        <cfset http_method = "POST">
        <cfset request_url = "http://api.twitter.com/oauth/request_token">
        <cfset oauth_consumer_secret = "#application.twitter_consumer_secret#">
        <cfset params = StructNew()>
        <cfset params["oauth_callback"] = "#application.twitter_redirecturl#?#session.URLToken#&returnFromTwitter=true">
        <cfset params["oauth_consumer_key"] = "#application.twitter_consumer_key#">
        <cfset params["oauth_nonce"] = DateFormat(Now(),'yymmdd') & TimeFormat (Now(),'hhmmssl')>
        <cfset params["oauth_signature_method"] = "HMAC-SHA1">
        <cfset params["oauth_timestamp"] = DateDiff("s", "January 1 1970 00:00", (Now()+(gmt_time_zone/24)))>
        <cfset params["oauth_version"] = "1.0">
        <!--- Submit OAuth request --->
        <cfset oauth_response = oauth_request(oauth_consumer_secret,"",http_method,request_url,params)>
        <!--- Parse and store the results --->
        <!--- Request Token (variable-length) --->
        <cfset oauth_token_start = Find("oauth_token=",oauth_response)+12>
        <cfset oauth_token_end = Find("&",oauth_response,oauth_token_start)>
        <cfset session.oauth_request_token = Mid(oauth_response,oauth_token_start,(oauth_token_end-oauth_token_start))>
        <!--- Request Token secret (variable-length)                       --->
        <cfset oauth_token_secret_start = Find("oauth_token_secret=",oauth_response)+19>
        <cfset oauth_token_secret_end = Find("&",oauth_response,oauth_token_secret_start)>
        <cfset session.oauth_request_token_secret = Mid(oauth_response,oauth_token_secret_start,(oauth_token_secret_end-oauth_token_secret_start))>
        <!--- Callback confirmation flag (true/false) --->
        <!--- ignored --->
        <!--- Forward user to Twitter for authentication --->
        <cflocation url="https://api.twitter.com/oauth/authorize?oauth_token=#session.oauth_request_token#">
    </cffunction>
    <!--- ************************************************************ --->
    <!--- OAUTH CALLBACK PAGE / GET OAUTH ACCESS TOKEN                 --->
    <!---                                                              --->
    <!---   Fourth, fifth and sixth steps of OAuth procedure (in       --->
    <!---   Twitter's OAuth diagram).  This is our "callback" page,    --->
    <!---   where the provider (e.g., Twitter) forwards users upon     --->
    <!---   successful authentication, along with a new verification   --->
    <!---   token (Step D).                                            --->
    <!---                                                              --->
    <!---   Next, the verification token is sent to the provider       --->
    <!---   (Step E) in exchange for an Access Token (Step F).  This   --->
    <!---   is the final authentication request.  Store the Access     --->
    <!---   Token in a database, for example, as you would a username  --->
    <!---   and password under Basic Authentication.                   --->
    <!---                                                              --->
    <!--- AUTHOR                                                       --->
    <!---   Dave Delbridge, Circa 3000 (http://circa3000.com)          --->
    <!---                                                              --->
    <!--- INPUT                                                        --->
    <!---   URL.OAUTH_TOKEN = copy of Request Token, sent from         --->
    <!---     Twitter, should match session.oauth_token                --->
    <!---   URL.OAUTH_VERIFIER = verifier sent from Twitter            --->
    <!---   URL.CFID = CF session state var specified in Callback URL  --->
    <!---   URL.CFTOKEN = ditto                                        --->
    <!---   SESSION.OAUTH_REQUEST_TOKEN = Request Token received in    --->
    <!---     Step B                                                   --->
    <!---   SESSION.OAUTH_REQUEST_TOKEN_SECRET = Request Token Secret  --->
    <!---     from Step B                                              --->
    <!---                                                              --->
    <!--- OUTPUT                                                       --->
    <!---   OAUTH_ACCESS_TOKEN = access token returned from provider   --->
    <!---   OAUTH_ACCESS_TOKEN_SECRET = key returned from provider     --->
    <!---                                                              --->
    <!--- ************************************************************ --->
    <cffunction name="get_access_token" access="remote" output="yes">
        <!--- Variables --->
        <cfset gmt_time_zone = "8"> <!--- Greenwich mean time offset at server --->
        <cfset http_method = "POST">
        <cfset request_url = "http://api.twitter.com/oauth/access_token">
        <cfset oauth_consumer_secret = "#application.twitter_consumer_secret#">
        <cfset params = StructNew()>
        <cfset params["oauth_consumer_key"] = "#application.twitter_consumer_key#">
        <cfset params["oauth_nonce"] = DateFormat(Now(),'yymmdd') & TimeFormat (Now(),'hhmmssl')>
        <cfset params["oauth_signature_method"] = "HMAC-SHA1">
        <cfset params["oauth_timestamp"] = DateDiff("s", "January 1 1970 00:00", (Now()+(gmt_time_zone/24)))>
        <cfset params["oauth_token"] = url.oauth_token>
        <cfset params["oauth_verifier"] = url.oauth_verifier>
        <cfset params["oauth_version"] = "1.0">
        <!--- Submit OAuth request --->
        <cfset oauth_response = oauth_request(oauth_consumer_secret,session.oauth_request_token_secret,http_method,request_url,params)>
        <!--- Get token (variable-length) --->
        <cfset oauth_token_start = Find("oauth_token=",oauth_response)+12>
        <cfset oauth_token_end = Find("&",oauth_response,oauth_token_start)>
        <cfset oauth_access_token = Mid(oauth_response,oauth_token_start,(oauth_token_end-oauth_token_start))>
        <!--- Get token secret (variable-length) --->
        <cfset oauth_token_secret_start = Find("oauth_token_secret=",oauth_response)+19>
        <cfset oauth_token_secret_end = Find("&",oauth_response,oauth_token_secret_start)>
        <cfset oauth_access_token_secret = Mid(oauth_response,oauth_token_secret_start,(oauth_token_secret_end-oauth_token_secret_start))>
        <!--- Set up the SESSION vars --->
        <cfset application.twitter_access_token = oauth_access_token>
        <cfset application.twitter_access_token_secret = oauth_access_token_secret>
    </cffunction>
    <!--- ************************************************************ --->
    <!--- GET BASICS TWITTER ACCOUNT SETTINGS FOR THIS USER            --->
    <!--- Dave White @cfJquery (http://cfjquery.com)                   --->
    <!--- ************************************************************ --->
    <cffunction name="get_twitter_details" access="remote" output="no">
        <cfset gmt_time_zone = "8"> <!--- Greenwich mean time offset at server --->
        <cfset http_method = "POST">
        <cfset request_url = "https://api.twitter.com/1.1/account/settings.json">
        <cfset oauth_consumer_secret = "#application.twitter_consumer_secret#">
        <cfset params = StructNew()>
        <cfset params["oauth_consumer_key"] = "#application.twitter_consumer_key#">
        <cfset params["oauth_nonce"] = DateFormat(Now(),'yymmdd') & TimeFormat (Now(),'hhmmssl')>
        <cfset params["oauth_signature_method"] = "HMAC-SHA1">
        <cfset params["oauth_token"] = "#application.twitter_access_token#">
        <cfset params["oauth_timestamp"] = DateDiff("s", "January 1 1970 00:00", (Now()+(gmt_time_zone/24)))>
        <cfset params["oauth_version"] = "1.0">
        <!--- Submit OAuth request --->
        <cfset oauth_response = oauth_request(oauth_consumer_secret,application.twitter_access_token_secret,http_method,request_url,params)>
        <!--- Display the results --->
        <cfreturn oauth_response>
    </cffunction>
    <!--- ************************************************************ --->
    <!--- INITIAL CALL TO FACEBOOK,LINKEDIN OR GOOGLE                  --->
    <!--- Dave White @cfJquery (http://cfjquery.com)                   --->
    <!--- ************************************************************ --->
    <cffunction name="initiate_login" access="remote" output="no">
        <cfargument name="loginUrlBase" type="string" required="true">
        <cfargument name="loginClientID" type="string" required="true">
        <cfargument name="loginRedirectURI" type="string" required="true">
        <cfargument name="loginScope" type="string" required="true">
        <cfset application.login_state = createUUID()>
        <cfset urlString = "">
        <cfset urlString = urlString & arguments.loginUrlBase>
        <cfset urlString = urlString & "?client_id=">
        <cfset urlString = urlString & arguments.loginClientID>
        <cfset urlString = urlString & "&redirect_uri=">
        <cfset urlString = urlString & arguments.loginRedirectURI>
        <cfset urlString = urlString & "&state=">
        <cfset urlString = urlString & application.login_state>
        <cfset urlString = urlString & "&scope=">
        <cfset urlString = urlString & arguments.loginScope>
        <cfset urlString = urlString & "&response_type=code">
        <cflocation url="#urlString#" addtoken="false">
    </cffunction>
    <!--- ************************************************************ --->
    <!--- AUTHORISATION CALL TO FACEBOOK,LINKEDIN OR GOOGLE            --->
    <!--- Dave White @cfJquery (http://cfjquery.com)                   --->
    <!--- ************************************************************ --->
    <cffunction name="authorise_login" access="remote" output="no">
        <cfargument name="authUrlBase" type="string" required="true">
        <cfargument name="authRedirectURI" type="string" required="true">
        <cfargument name="authMethod" type="string" required="true">
        <cfargument name="authCode" type="string" required="true">
        <cfargument name="authClientId" type="string" required="true">
        <cfargument name="authClientSecret" type="string" required="true">
        <cfargument name="authGrantType" type="string" required="true">
        <cfset urlBody = "">
        <cfset urlBody = urlBody & "code=">
        <cfset urlBody = urlBody & arguments.authCode>
        <cfset urlBody = urlBody & "&redirect_uri=">
        <cfset urlBody = urlBody & arguments.authRedirectURI>
        <cfset urlBody = urlBody & "&client_id=">
        <cfset urlBody = urlBody & arguments.authClientId>
        <cfset urlBody = urlBody & "&client_secret=">
        <cfset urlBody = urlBody & arguments.authClientSecret>
        <cfset urlBody = urlBody & "&grant_type=">
        <cfset urlBody = urlBody & arguments.authGrantType>
        <!--- Get the ACCESS TOKEN --->
        <cfhttp url="#arguments.authUrlBase#" result="httpResult" method="#arguments.authMethod#" resolveurl="true">
            <cfhttpparam type="header" name="Content-Type" value="application/x-www-form-urlencoded">
            <cfhttpparam type="body" value="#urlBody#">
        </cfhttp>
        <cfreturn httpResult>
    </cffunction>
</cfcomponent>